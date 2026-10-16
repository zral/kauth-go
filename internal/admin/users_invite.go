package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const (
	// Kvoten er per bruker, uavhengig av leverandør: en kompromittert admin-sesjon
	// skal ikke kunne bruke brukerens innboks til å sende ut lenker i bulk.
	linkInviteMax    = 5
	linkInviteWindow = time.Hour
)

var errInviteRateLimited = errors.New("for mange invitasjoner")

// linkInviteMailer er det invitasjonene trenger av mail.Service; tester bytter den ut.
type linkInviteMailer interface {
	SendLinkInvite(to, fromName, linkURL, providerName, locale, fromAddress string) error
}

// inviteDeps samler det koblingsinvitasjonene trenger utover brukerhåndteringen.
type inviteDeps struct {
	idps    *idp.Registry
	mailer  linkInviteMailer
	baseURL string
	sendWG  sync.WaitGroup
	now     func() time.Time
}

// WithInvites kobler på koblingsinvitasjonene. baseURL er KAUTH_BASE_URL, brukt
// for tjenester uten eget auth_host.
func (h *UsersHandler) WithInvites(idps *idp.Registry, mailer linkInviteMailer, baseURL string) *UsersHandler {
	h.inv = &inviteDeps{idps: idps, mailer: mailer, baseURL: baseURL, now: time.Now}
	return h
}

// WaitForSends venter på asynkrone invitasjonsmailer (tester og nedstenging).
// Trygg å kalle uten WithInvites.
func (h *UsersHandler) WaitForSends() {
	if h.inv != nil {
		h.inv.sendWG.Wait()
	}
}

// inviteView er en aktiv invitasjon slik admin ser den. Aldri token eller hash.
type inviteView struct {
	ID        int64
	Provider  string
	Service   string
	ExpiresAt string
	CreatedBy string
}

// inviteOption er et gyldig (leverandør, tjeneste)-par i nedtrekket.
type inviteOption struct {
	Value string // slug:tjeneste
	Label string
}

// inviteData gir malen aktive invitasjoner og gyldige par.
func (h *UsersHandler) inviteData(ctx context.Context, u gen.User) (views []inviteView, opts []inviteOption, err error) {
	if h.inv == nil {
		return nil, nil, nil
	}
	rows, err := h.queries.ListActiveLinkInvitesByUser(ctx, gen.ListActiveLinkInvitesByUserParams{
		UserID: u.ID, Now: token.FormatLinkInviteTime(h.inv.now()),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list invitasjoner: %w", err)
	}
	provs, err := h.queries.ListAllIdentityProviders(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list leverandører: %w", err)
	}
	names := make(map[int64]string, len(provs))
	for _, p := range provs {
		names[p.ID] = p.DisplayName
	}
	for _, r := range rows {
		views = append(views, inviteView{
			ID: r.ID, Provider: names[r.ProviderID], Service: r.ServiceID,
			ExpiresAt: r.ExpiresAt, CreatedBy: r.CreatedBy,
		})
	}
	if u.DeactivatedAt != nil {
		return views, nil, nil
	}
	svcs, err := h.queries.ListAllServices(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list tjenester: %w", err)
	}
	for _, s := range svcs {
		if s.Active != 1 {
			continue
		}
		for _, p := range h.inv.idps.ForService(s.ID) {
			opts = append(opts, inviteOption{Value: p.Slug + ":" + s.ID, Label: p.DisplayName + " på " + s.ID})
		}
	}
	return views, opts, nil
}

// HandleInviteCreate sender en koblingsinvitasjon til brukerens registrerte
// adresse. Lenken vises aldri her, og tokenet lagres bare som hash.
func (h *UsersHandler) HandleInviteCreate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || h.inv == nil {
		http.NotFound(w, r)
		return
	}
	user, err := h.queries.GetUserByID(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	_ = r.ParseForm()
	slug, svcID := r.PostFormValue("provider"), r.PostFormValue("service")
	if slug == "" && svcID == "" {
		slug, svcID, _ = strings.Cut(r.PostFormValue("pair"), ":")
	}

	email := token.NormalizeEmail(user.Email)
	if user.DeactivatedAt != nil || !token.ValidEmail(email) {
		h.renderInviteError(w, r, user, http.StatusUnprocessableEntity, "Brukeren er deaktivert eller mangler e-postadresse.")
		return
	}
	prov, ok := h.inv.idps.Get(slug)
	if !ok {
		h.renderInviteError(w, r, user, http.StatusUnprocessableEntity, "Leverandøren er ikke lastet.")
		return
	}
	svc, err := findServiceByID(r.Context(), h.queries, svcID)
	if err != nil {
		slog.Error("admin: oppslag av tjeneste feilet", "service_id", svcID, "error", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if svc == nil || svc.Active != 1 {
		h.renderInviteError(w, r, user, http.StatusUnprocessableEntity, "Tjenesten finnes ikke eller er deaktivert.")
		return
	}
	assigned := false
	for _, p := range h.inv.idps.ForService(svc.ID) {
		if p.ID == prov.ID {
			assigned = true
		}
	}
	if !assigned {
		h.renderInviteError(w, r, user, http.StatusUnprocessableEntity, "Leverandøren er ikke tilordnet tjenesten.")
		return
	}

	plain, hash, err := token.NewLinkInviteToken()
	if err != nil {
		slog.Error("admin: kunne ikke lage invitasjonstoken", "error", err)
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}

	// WithoutCancel: brenning, innsetting og audit hører sammen og skal ikke
	// stoppes halvveis av at admin kobler fra.
	ctx := context.WithoutCancel(r.Context())
	now := h.inv.now().UTC()
	var inviteID int64
	err = token.RunInTx(ctx, h.sqlDB, func(q *gen.Queries) error {
		// Brenn først, sett inn etterpå: gir innsettingen 0 rader (kvote), rulles
		// brenningen tilbake og forrige invitasjon står.
		if _, err := q.BurnLinkInvites(ctx, gen.BurnLinkInvitesParams{
			Now: token.FormatLinkInviteTime(now), UserID: user.ID, ProviderID: prov.ID,
		}); err != nil {
			return err
		}
		n, err := q.InsertLinkInviteLimited(ctx, gen.InsertLinkInviteLimitedParams{
			TokenHash: hash, UserID: user.ID, ProviderID: prov.ID, ServiceID: svc.ID,
			Email: email, CreatedBy: ActorFromContext(ctx),
			CreatedAt:   token.FormatLinkInviteTime(now),
			ExpiresAt:   token.FormatLinkInviteTime(now.Add(token.LinkInviteTTL)),
			WindowStart: token.FormatLinkInviteTime(now.Add(-linkInviteWindow)),
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errInviteRateLimited
		}
		row, err := q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{
			TokenHash: hash, Now: token.FormatLinkInviteTime(now),
		})
		inviteID = row.ID
		return err
	})
	if errors.Is(err, errInviteRateLimited) {
		h.renderInviteError(w, r, user, http.StatusTooManyRequests, "For mange invitasjoner siste time.")
		return
	}
	if err != nil {
		slog.Error("admin: opprettelse av koblingsinvitasjon feilet", "id", id, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	// Aldri token eller lenke i audit.
	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:    "identity_link_invited",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d invite=%d provider=%s service=%s", id, inviteID, prov.Slug, svc.ID),
	})

	if !auditOK {
		// Lukket feiling: uten auditspor skal ingen lenke være ute. Raden brukes
		// opp i stedet for slettes, så kvoteraden består.
		if _, err := h.queries.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{
			Now: token.FormatLinkInviteTime(h.inv.now()), ID: inviteID, UserID: id,
		}); err != nil {
			slog.Error("admin: kunne ikke trekke tilbake invitasjon etter audit-feil", "invite", inviteID, "error", err)
		}
		h.renderInviteError(w, r, user, http.StatusInternalServerError, "Invitasjonen ble ikke sendt fordi audit-loggen ikke kunne skrives. Prøv igjen.")
		return
	}

	link := service.LinkBaseURL(h.inv.baseURL, svc) + "/link/" + plain
	fromName, fromAddress := svc.EmailFromName, ""
	if svc.EmailFromAddress != nil {
		fromAddress = *svc.EmailFromAddress
	}
	// Verken tjenester eller brukere har språkfelt. Admin velger språket ved å
	// sende fra en nettleser med ønsket språk (Accept-Language), som for magic link.
	locale := i18n.FromRequest(r)
	// Asynkront slik at SMTP-latens ikke holder admin-requesten; raden er lagret.
	// Feil logges uten lenke og adresse.
	h.inv.sendWG.Add(1)
	go func() {
		defer h.inv.sendWG.Done()
		if err := h.inv.mailer.SendLinkInvite(email, fromName, link, prov.DisplayName, locale, fromAddress); err != nil {
			slog.Error("admin: kunne ikke sende koblingsinvitasjon", "invite", inviteID, "error", err)
		}
	}()

	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d/edit?invite=sent", id), http.StatusSeeOther)
}

// HandleInviteRevoke trekker tilbake en aktiv invitasjon. user_id i vilkåret
// gjør at en invitasjon for en annen bruker gir 404.
func (h *UsersHandler) HandleInviteRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	inviteID, err := strconv.ParseInt(chi.URLParam(r, "inviteID"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := context.WithoutCancel(r.Context())
	now := time.Now()
	if h.inv != nil {
		now = h.inv.now()
	}
	n, err := h.queries.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{
		Now: token.FormatLinkInviteTime(now), ID: inviteID, UserID: id,
	})
	if err != nil {
		slog.Error("admin: tilbaketrekking av invitasjon feilet", "id", id, "invite", inviteID, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.NotFound(w, r)
		return
	}
	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:    "identity_link_invite_revoked",
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d invite=%d", id, inviteID),
	})
	if !auditOK {
		http.Redirect(w, r, usersRedirect(false), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%d/edit", id), http.StatusSeeOther)
}

// renderInviteError viser redigeringssiden på nytt med feilen.
func (h *UsersHandler) renderInviteError(w http.ResponseWriter, r *http.Request, user gen.User, status int, msg string) {
	data, err := h.editData(r.Context(), user)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	data["InviteError"] = msg
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = h.editTpl.Execute(w, data)
}
