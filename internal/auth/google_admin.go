package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// AdminSessionStarter lar OIDC-callbacken starte en admin-sesjon uten at auth
// kjenner admin-cookie, TTL eller admin-audit. Implementasjonen ligger i
// internal/admin (som ikke kan importeres herfra uten syklus) og injiseres fra
// main.go. Kalleren har allerede verifisert at brukeren er aktiv og har
// rollen konge.
type AdminSessionStarter interface {
	StartAdminSession(w http.ResponseWriter, r *http.Request, user gen.User, serviceID string) error
}

// auditAdminFailure skriver admin_google_login med success=0.
func (h *GoogleHandlers) auditAdminFailure(r *http.Request, svc *gen.Service, email, details string) {
	h.aud.Log(r.Context(), audit.Event{Type: "admin_google_login", AuthMethod: "google", Email: email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: details})
}

// errAdminBindRollback ruller tilbake binding når identiteten ikke lot seg godkjenne.
var errAdminBindRollback = errors.New("admin-binding rullet tilbake")

// completeAdminLogin avslutter en OIDC-flyt med admin-formål. Den slår bare opp
// en eksisterende aktiv bruker: ingen auto-registrering og ingen tjenestepolicy
// (admin er ikke bundet til en tjeneste). Rollen konge kreves med eksakt match,
// og Google må ha bekreftet e-postadressen. Ingen JWT havner i URL-en;
// sesjonen settes som cookie av AdminSessionStarter.
func (h *GoogleHandlers) completeAdminLogin(w http.ResponseWriter, r *http.Request, svc *gen.Service, cl googleClaims) {
	ctx := r.Context()
	reject := func(email, details string) {
		h.auditAdminFailure(r, svc, email, details)
		redirectAdminLoginError(w, r)
	}
	// Normalisert slik at oppslaget ikke avhenger av hvordan Google skriver adressen.
	email := NormalizeEmail(cl.Email)
	if email == "" {
		reject("", "mangler e-post i id_token")
		return
	}
	if !cl.EmailVerified {
		reject(email, "e-post ikke verifisert av Google")
		return
	}
	ext, ok := googleIdentity(cl, email)
	if !ok {
		reject(email, "mangler sub eller ugyldig issuer i id_token")
		return
	}
	// Ingen auto-kobling utover overgangen og ingen auto-registrering (PD8):
	// admin-tilgang skal ikke følge av at noen kontrollerer en adresse hos Google.
	user, idn, _, err := h.resolver.resolveIdentity(ctx, ext, linkPolicy{}, resolveMeta{ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent")})
	if err != nil {
		if !errors.Is(err, errNoAccount) && !errors.Is(err, errUserInactive) && !errors.Is(err, errLinkDenied) {
			slog.Error("google: admin-oppslag feilet", "error", err)
		}
		reject(email, "ukjent, deaktivert eller ikke koblet")
		return
	}
	if !csvHasExact(user.Roles, "konge") {
		reject(email, "mangler konge-rolle")
		return
	}
	// Koblinger er globale: en identitet koblet via en vanlig tjeneste er ikke
	// dermed godkjent for admin. Første admin-innlogging for en ubundet bruker
	// binder brukeren (BindAdmin, bare én gang) og godkjenner identiteten i samme
	// transaksjon. En bundet bruker uten godkjent identitet avvises: en frakoblet
	// admin-identitet skal ikke kunne erstattes av en ny ved neste innlogging.
	if idn.AdminOk != 1 {
		boundAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		res, err := bindAdminIdentity(ctx, h.sqlDB, user.ID, idn.ID, boundAt)
		if err != nil {
			slog.Error("google: kunne ikke binde admin-identitet", "error", err)
			reject(email, "intern feil")
			return
		}
		if res != adminBound {
			reason := "not_admin_identity"
			if res == adminIdentityVanished {
				reason = "identity_vanished"
			}
			h.aud.Log(context.WithoutCancel(ctx), audit.Event{Type: "identity_link_denied", AuthMethod: "google", Email: user.Email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: "reason=" + reason})
			reject(email, "identitet ikke godkjent for admin")
			return
		}
		h.aud.Log(context.WithoutCancel(ctx), audit.Event{Type: "identity_admin_approved", AuthMethod: "google", Email: user.Email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: true, Details: "provider=" + ext.Provider + " issuer=" + ext.Issuer + " bound=1"})
	}
	if h.adminSessions == nil {
		slog.Error("google: admin-flyt uten AdminSessionStarter")
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	if err := h.adminSessions.StartAdminSession(w, r, user, svc.ID); err != nil {
		slog.Error("google: kunne ikke starte admin-sesjon", "email", user.Email, "error", err)
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

type adminBindResult int

const (
	adminBound            adminBindResult = iota
	adminAlreadyBound                     // brukeren er bundet fra før: ny identitet godkjennes ikke
	adminIdentityVanished                 // identiteten forsvant mellom oppslag og godkjenning
)

// bindAdminIdentity binder brukeren og godkjenner identiteten i én transaksjon.
// Mislykkes godkjenningen, rulles bindingen tilbake så brukeren ikke står bundet
// uten en godkjent identitet.
func bindAdminIdentity(ctx context.Context, sqlDB *sql.DB, userID, identityID int64, boundAt string) (adminBindResult, error) {
	res := adminAlreadyBound
	err := token.RunInTx(ctx, sqlDB, func(q *gen.Queries) error {
		n, err := q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &boundAt, ID: userID})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		n, err = q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: identityID, UserID: userID, BoundAt: &boundAt})
		if err != nil {
			return err
		}
		if n == 0 {
			return errAdminBindRollback
		}
		res = adminBound
		return nil
	})
	if errors.Is(err, errAdminBindRollback) {
		return adminIdentityVanished, nil
	}
	return res, err
}
