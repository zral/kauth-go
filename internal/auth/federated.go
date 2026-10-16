package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

// federatedProvider er det som skiller Google og Microsoft i den felles
// stien etter at leverandøren har verifisert id_token. Bevisst en struct og
// ikke et interface: leverandørene deler ingen flyt, bare avslutningen.
type federatedProvider struct {
	login        loginMethod
	rejectedType string // audit-type for avvisning, f.eks. google_oidc_rejected
}

var (
	providerGoogle    = federatedProvider{login: loginGoogle, rejectedType: "google_oidc_rejected"}
	providerMicrosoft = federatedProvider{login: loginMicrosoft, rejectedType: "microsoft_oidc_rejected"}
)

// federatedLogin samler det den felles stien trenger. Lages i New*Handlers
// og deler pekere med handleren.
type federatedLogin struct {
	resolver  *identityResolver
	completer *loginCompleter
	aud       *audit.Service
}

// readState krever at state-cookien finnes, er lik state-parameteren og har
// gyldig signatur. Ellers redirectes det uten tjeneste og uten audit: en
// ugyldig state sier ikke noe pålitelig om hvilken tjeneste det gjelder.
// Admin-formålet ligger i claims.Admin og tolkes av kalleren.
func readState(w http.ResponseWriter, r *http.Request, cookieName string, secret []byte) (stateClaims, bool) {
	sc, err := r.Cookie(cookieName)
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return stateClaims{}, false
	}
	claims, ok := parseState(secret, sc.Value)
	if !ok {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return stateClaims{}, false
	}
	return claims, true
}

// rejection beskriver et avvist forsøk. Context (f.eks. tid=…) står foran
// årsaken i Details når den er satt.
type rejection struct {
	Email, Context, Reason string
}

func (rej rejection) details() string {
	d := "reason=" + rej.Reason
	if rej.Context != "" {
		d = rej.Context + " " + d
	}
	return d
}

func (f *federatedLogin) auditRejected(r *http.Request, p federatedProvider, svcID string, rej rejection) {
	f.aud.Log(r.Context(), audit.Event{Type: p.rejectedType, AuthMethod: p.login.AuthMethod, Email: rej.Email, ServiceID: svcID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: rej.details()})
}

// reject auditerer og sender brukeren tilbake med generisk feil. Teknisk
// årsak går til audit, aldri til responsen.
func (f *federatedLogin) reject(w http.ResponseWriter, r *http.Request, p federatedProvider, svc *gen.Service, rej rejection) {
	f.auditRejected(r, p, svc.ID, rej)
	redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
}

// finish slår opp eller oppretter brukeren for en verifisert ekstern
// identitet og utsteder tokens. Policyavslag og manglende konto gir
// access_denied uten å si hvilket; alt annet som feiler gir login_failed.
func (f *federatedLogin) finish(w http.ResponseWriter, r *http.Request, p federatedProvider, svc *gen.Service, ext externalIdentity) {
	user, _, err := f.resolver.resolve(r.Context(), ext, policyFor(svc), resolveMeta{ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent")})
	if err != nil {
		switch {
		case errors.Is(err, errNoAccount):
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		case errors.Is(err, errUserInactive):
			f.auditRejected(r, p, svc.ID, rejection{Email: ext.Email, Reason: "user_inactive"})
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		case errors.Is(err, errLinkDenied):
			redirectLoginError(w, r, svc.ID, errCodeAccountNotLinked)
		case errors.Is(err, errUserConflict):
			slog.Warn(p.login.LogPrefix+": auto-registrering kolliderte med eksisterende rad", "service", svc.ID, "error", err)
			f.reject(w, r, p, svc, rejection{Email: ext.Email, Reason: "user_conflict"})
		default:
			slog.Error(p.login.LogPrefix+": kunne ikke finne eller opprette bruker", "error", err)
			redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		}
		return
	}
	if err := f.completer.complete(w, r, svc, user, p.login); err != nil {
		if errors.Is(err, errPolicyDenied) {
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		} else {
			redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		}
	}
}
