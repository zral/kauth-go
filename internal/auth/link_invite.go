package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// linkTokenLen er lengden på et invitasjonstoken: 32 byte som base64url uten
// padding (token.NewLinkInviteToken).
const linkTokenLen = 43

// linkMailer lar tester telle kvitteringsmailer uten å fange stdout.
type linkMailer interface {
	SendLinkConfirmation(to, fromName, providerName, locale, fromAddress string) error
}

// LinkHandlers er brukersiden av koblingsinvitasjoner (016): bekreftelsessiden
// på /link/{token} og avslutningen av koblingen når leverandøren har sendt
// brukeren tilbake. Admin-siden ligger i internal/admin.
type LinkHandlers struct {
	cfg    config.Config
	sqlDB  *sql.DB
	q      *gen.Queries
	reg    *service.Registry
	idps   *idp.Registry
	aud    *audit.Service
	tmpl   *template.Template
	mailer linkMailer
	sendWG sync.WaitGroup // lar tester og nedstenging vente på kvitteringsmail
}

func NewLinkHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, reg *service.Registry, idps *idp.Registry, aud *audit.Service, tmpl *template.Template, mailer linkMailer) *LinkHandlers {
	return &LinkHandlers{cfg: cfg, sqlDB: sqlDB, q: q, reg: reg, idps: idps, aud: aud, tmpl: tmpl, mailer: mailer}
}

// WaitForSends venter til kvitteringsmail er sendt (tester og nedstenging).
func (l *LinkHandlers) WaitForSends() { l.sendWG.Wait() }

// linkTarget er en invitasjon som har bestått alle sjekker.
type linkTarget struct {
	invite   gen.IdentityLinkInvite
	user     gen.User
	provider idp.Provider
	svc      *gen.Service
}

func validLinkTokenFormat(t string) bool {
	if len(t) != linkTokenLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// lookup er felles for GET og POST. Alle avslag gir bare false: kalleren
// viser den samme generiske siden uansett årsak, så ingen kan lese av om et
// token fantes, var brukt eller tilhørte en deaktivert bruker (K12).
func (l *LinkHandlers) lookup(ctx context.Context, raw string) (linkTarget, bool) {
	if !validLinkTokenFormat(raw) {
		return linkTarget{}, false
	}
	inv, err := l.q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{
		TokenHash: token.HashOpaque(raw),
		Now:       token.FormatLinkInviteTime(time.Now()),
	})
	if err != nil {
		return linkTarget{}, false
	}
	user, err := l.q.GetUserByID(ctx, inv.UserID)
	// Invitasjonen er bundet til e-posten brukeren hadde da den ble laget (K26).
	if err != nil || user.DeactivatedAt != nil || NormalizeEmail(user.Email) != inv.Email {
		return linkTarget{}, false
	}
	svc := l.reg.Resolve("", inv.ServiceID, "")
	if svc == nil || svc.Active != 1 {
		return linkTarget{}, false
	}
	for _, p := range l.idps.ForService(svc.ID) {
		if p.ID == inv.ProviderID {
			return linkTarget{invite: inv, user: user, provider: p, svc: svc}, true
		}
	}
	return linkTarget{}, false
}

// maskEmail viser første tegn i lokaldelen og hele domenet: k***@firma.no.
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	first := []rune(email[:at])[0]
	return string(first) + "***" + email[at:]
}

// linkPageData er maldata for link-confirm.html og link-result.html.
type linkPageData struct {
	Service     *gen.Service
	LogoHTML    template.HTML
	BodyBgCSS   template.CSS
	BeforeBgCSS template.CSS
	Locale      string
	T           i18n.Strings
	Languages   []i18n.Link
	Title       string
	Hint        string
	Button      string
	// HintParts er Hint delt slik at leverandørnavn og e-post kan vises
	// uthevet uten at brukerdata rendres som rå HTML.
	HintParts []linkTextPart
	// Action er stien skjemaet POST-er til (samme sti som GET).
	Action  string
	IsError bool
	// langURL er URL-en språkvelgeren bygges fra. Settes bare for bekreftelses-
	// siden: på de andre sidene bærer r.URL token eller code og state, som ikke
	// skal inn i href-ene, så de har ingen språkvelger.
	langURL *url.URL
}

type linkTextPart struct {
	Text   string
	Strong bool
}

// splitLinkText setter inn provider og email som uthevede deler.
func splitLinkText(s, provider, email string) []linkTextPart {
	var parts []linkTextPart
	for len(s) > 0 {
		i, val := -1, ""
		for _, ph := range []struct{ tag, val string }{{"{provider}", provider}, {"{email}", email}} {
			if j := strings.Index(s, ph.tag); j >= 0 && (i < 0 || j < i) {
				i, val = j, ph.val
			}
		}
		if i < 0 {
			parts = append(parts, linkTextPart{Text: s})
			break
		}
		if i > 0 {
			parts = append(parts, linkTextPart{Text: s[:i]})
		}
		parts = append(parts, linkTextPart{Text: val, Strong: true})
		end := strings.IndexByte(s[i:], '}') + i + 1
		s = s[end:]
	}
	return parts
}

func fillLinkText(s, provider, email string) string {
	return strings.NewReplacer("{provider}", provider, "{email}", email).Replace(s)
}

// render skriver en side med tjenestens tema. Sidene bærer et engangstoken i
// stien (eller hører til en flyt som gjør det) og må ikke caches eller lekke
// stien i Referer.
func (l *LinkHandlers) render(w http.ResponseWriter, r *http.Request, svc *gen.Service, status int, name string, data linkPageData) {
	if svc == nil {
		svc = &gen.Service{DisplayName: "kauth", Theme: "light"}
	}
	locale := i18n.FromRequest(r)
	data.Service = svc
	data.LogoHTML = logoHTMLFor(svc)
	data.BodyBgCSS, data.BeforeBgCSS = buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	data.Locale = locale
	data.T = i18n.Get(locale)
	if data.langURL != nil {
		data.Languages = i18n.Links(locale, data.langURL)
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Vary", "Accept-Language")
	w.WriteHeader(status)
	if err := l.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("link: kunne ikke rendre siden", "page", name, "error", err)
	}
}

// renderInvalid er det ene svaret for alle ugyldige lenker. Temaet kommer fra
// vert, ikke fra invitasjonen, slik at siden er lik uansett hvorfor lenken
// ikke virker.
func (l *LinkHandlers) renderInvalid(w http.ResponseWriter, r *http.Request) {
	t := i18n.Get(i18n.FromRequest(r))
	l.render(w, r, l.reg.ResolveOrDefault(r.Host, "", ""), http.StatusOK, "link-result.html",
		linkPageData{Title: t.LinkInvalidTitle, Hint: t.LinkInvalidHint, IsError: true})
}

func (l *LinkHandlers) renderResult(w http.ResponseWriter, r *http.Request, svc *gen.Service, status int, kind, providerName string) {
	t := i18n.Get(i18n.FromRequest(r))
	d := linkPageData{}
	switch kind {
	case "done":
		d.Title, d.Hint = t.LinkDoneTitle, fillLinkText(t.LinkDoneHint, providerName, "")
	case "already":
		d.Title, d.Hint = t.LinkAlreadyTitle, fillLinkText(t.LinkAlreadyHint, providerName, "")
	default:
		d.Title, d.Hint, d.IsError = t.LinkRejectedTitle, t.LinkRejectedHint, true
	}
	l.render(w, r, svc, status, "link-result.html", d)
}

// ShowConfirm — GET /link/{token}
// Viser bare en bekreftelsesside og endrer ingen tilstand: e-postklienter og
// lenkeskannere henter lenker med GET.
func (l *LinkHandlers) ShowConfirm(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "token")
	tg, ok := l.lookup(r.Context(), raw)
	if !ok {
		l.renderInvalid(w, r)
		return
	}
	locale := i18n.FromRequest(r)
	t := i18n.Get(locale)
	name := tg.provider.DisplayName
	l.render(w, r, tg.svc, http.StatusOK, "link-confirm.html", linkPageData{
		Title:     fillLinkText(t.LinkConfirmTitle, name, ""),
		HintParts: splitLinkText(t.LinkConfirmHint, name, maskEmail(tg.invite.Email)),
		Button:    fillLinkText(t.LinkConfirmButton, name, ""),
		Action:    "/link/" + url.PathEscape(raw) + "?" + url.Values{"lang": {locale}}.Encode(),
		langURL:   r.URL,
	})
}

// StartLink — POST /link/{token}
// Sender brukeren til leverandøren med en state som binder invitasjonen.
// Tokenet brukes ikke opp her: en avbrutt innlogging hos leverandøren skal
// ikke brenne lenken. Oppbruk skjer atomisk med koblingen i callbacken.
func (l *LinkHandlers) StartLink(w http.ResponseWriter, r *http.Request) {
	// Også uten fetchmeta.Middleware i ruten (forsvar i dybden).
	if !fetchmeta.SameOrigin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	tg, ok := l.lookup(r.Context(), chi.URLParam(r, "token"))
	if !ok {
		l.renderInvalid(w, r)
		return
	}
	slug := tg.provider.Slug
	d, err := l.idps.Discover(r.Context(), slug)
	if err != nil {
		slog.Warn("link: discovery feilet", "provider", slug, "reason", idp.DiscoveryReason(err))
		l.auditRejected(r, tg.svc.ID, tg.invite.ID, slug, "discovery", tg.user.Email)
		l.renderResult(w, r, tg.svc, http.StatusBadGateway, "rejected", "")
		return
	}
	nonce, err := generateNonce()
	if err != nil {
		slog.Error("link: kunne ikke lage nonce", "error", err)
		l.renderResult(w, r, tg.svc, http.StatusInternalServerError, "rejected", "")
		return
	}
	state := signLinkState(l.cfg.OIDCStateSecret, tg.svc.ID, nonce, slug, tg.invite.ID)
	oauthCfg := &oauth2.Config{
		ClientID:    tg.provider.ClientID,
		Endpoint:    d.Endpoint,
		RedirectURL: idpRedirectURL(r, slug),
		Scopes:      tg.provider.Scopes,
	}
	// Samme cookie som vanlig generisk innlogging, men ingen redirect_uri-cookie:
	// en kobling utsteder ikke tokens og sender ikke brukeren videre.
	http.SetCookie(w, &http.Cookie{
		Name:     idpStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// prompt=login tvinger ny autentisering hos leverandøren. Uten den kunne en
	// eksisterende SSO-økt koble en fremmed konto stille hvis noen lokker et
	// offer til å åpne en annens lenke. Vanlig innlogging bruker den ikke.
	authURL := oauthCfg.AuthCodeURL(state, oauth2.S256ChallengeOption(idp.PKCEVerifier(l.cfg.OIDCStateSecret, state)), oidc.Nonce(nonce), oauth2.SetAuthURLParam("prompt", "login"))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// linkRejection bærer årsaken til et avslag ut av transaksjonen, som dermed
// rulles tilbake.
type linkRejection struct{ reason string }

func (e linkRejection) Error() string { return "kobling avvist: " + e.reason }

// linkOutcome sier hva transaksjonen endte med.
type linkOutcome int

const (
	linkCreated linkOutcome = iota
	linkAlready
)

// finishLink avslutter en koblingsflyt etter at HandleCallback har verifisert
// state, sti, iss, kode med PKCE, id_token, azp, nonce og sub. Den utsteder
// aldri tokens eller sesjon og bruker aldri redirect_uri. E-postpåstanden i
// tokenet avgjør ikke koblingen; beviset er lenken pluss innloggingen.
func (l *LinkHandlers) finishLink(w http.ResponseWriter, r *http.Request, svc *gen.Service, p idp.Provider, inviteID int64, sub, rawEmail string) {
	// Klienten kan lukke forbindelsen midt i: transaksjonen skal likevel ende
	// helt eller ikke i det hele tatt.
	ctx := context.WithoutCancel(r.Context())
	now := time.Now()
	var claimed *string
	if rawEmailSafe(rawEmail) {
		e := NormalizeEmail(rawEmail)
		claimed = &e
	}

	var user gen.User
	var outcome linkOutcome
	var identityID int64
	err := token.RunInTx(ctx, l.sqlDB, func(q *gen.Queries) error {
		inv, err := q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{
			Now: token.FormatLinkInviteTime(now), ID: inviteID, ProviderID: p.ID, ServiceID: svc.ID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return linkRejection{"invite_invalid"}
		}
		if err != nil {
			return err
		}
		user, err = q.GetUserByID(ctx, inv.UserID)
		if errors.Is(err, sql.ErrNoRows) {
			return linkRejection{"invite_invalid"}
		}
		if err != nil {
			return err
		}
		if user.DeactivatedAt != nil {
			return linkRejection{"user_inactive"}
		}
		if NormalizeEmail(user.Email) != inv.Email {
			return linkRejection{"email_changed"}
		}
		// En eksisterende identitet overskrives aldri (K27): finnes (issuer,
		// sub) fra før, er den enten brukerens egen eller en fremmeds.
		decide := func(idn gen.UserIdentity) error {
			if idn.UserID != user.ID {
				return linkRejection{"identity_taken"}
			}
			outcome = linkAlready
			identityID = idn.ID
			return nil
		}
		idn, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: p.Issuer, Subject: sub})
		if err == nil {
			return decide(idn)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		ts := now.UTC().Format(time.RFC3339)
		n, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{
			UserID: user.ID, Provider: "oidc", Issuer: p.Issuer, Subject: sub,
			Email: claimed, CreatedAt: ts, LastUsedAt: &ts,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			// Noen la inn samme (issuer, sub) mellom lesing og skriving.
			idn, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: p.Issuer, Subject: sub})
			if err != nil {
				return err
			}
			return decide(idn)
		}
		idn, err = q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: p.Issuer, Subject: sub})
		if err != nil {
			return err
		}
		outcome = linkCreated
		identityID = idn.ID
		return nil
	})

	var rej linkRejection
	if errors.As(err, &rej) {
		// user er satt når raden ble funnet, ellers tom. Invitasjonen er ubrukt
		// etter rollback.
		l.auditRejected(r, svc.ID, inviteID, p.Slug, rej.reason, user.Email)
		l.renderResult(w, r, svc, http.StatusBadRequest, "rejected", p.DisplayName)
		return
	}
	if err != nil {
		slog.Error("link: kunne ikke fullføre koblingen", "invite", inviteID, "provider", p.Slug, "error", err)
		l.auditRejected(r, svc.ID, inviteID, p.Slug, "internal", user.Email)
		l.renderResult(w, r, svc, http.StatusInternalServerError, "rejected", p.DisplayName)
		return
	}

	details := fmt.Sprintf("via=invite invite=%d provider=%s issuer=%s identity_id=%d", inviteID, p.Slug, p.Issuer, identityID)
	if outcome == linkAlready {
		details += " already=1"
	}
	// Synkront: dette er eneste spor av en ny innloggingsvei, og en tapt
	// køhendelse (full kø) ville skjult den. Feil logges; koblingen står.
	if err := l.aud.LogSync(ctx, audit.Event{Type: "identity_linked", AuthMethod: loginOIDC.AuthMethod, Email: user.Email,
		ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: true, Details: details}); err != nil {
		slog.Error("link: kunne ikke auditere kobling", "invite", inviteID, "error", err)
	}

	if outcome == linkCreated {
		l.sendReceipt(r, svc, user.Email, p.DisplayName)
		l.renderResult(w, r, svc, http.StatusOK, "done", p.DisplayName)
		return
	}
	l.renderResult(w, r, svc, http.StatusOK, "already", p.DisplayName)
}

// sendReceipt sender kvitteringsmailen asynkront, slik at en videresendt
// invitasjon blir synlig for brukeren. Feil logges uten adresse.
func (l *LinkHandlers) sendReceipt(r *http.Request, svc *gen.Service, to, providerName string) {
	locale := i18n.FromRequest(r)
	var fromAddress string
	if svc.EmailFromAddress != nil {
		fromAddress = *svc.EmailFromAddress
	}
	fromName := svc.EmailFromName
	l.sendWG.Add(1)
	go func() {
		defer l.sendWG.Done()
		if err := l.mailer.SendLinkConfirmation(to, fromName, providerName, locale, fromAddress); err != nil {
			slog.Error("link: kunne ikke sende kvittering", "error", err)
		}
	}()
}

// auditRejected skriver identity_link_rejected. Details har aldri sub eller
// token.
func (l *LinkHandlers) auditRejected(r *http.Request, svcID string, inviteID int64, slug, reason, email string) {
	// Synkront av samme grunn som identity_linked.
	if err := l.aud.LogSync(r.Context(), audit.Event{Type: "identity_link_rejected", AuthMethod: loginOIDC.AuthMethod, Email: email,
		ServiceID: svcID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false,
		Details: fmt.Sprintf("invite=%d provider=%s reason=%s", inviteID, slug, reason)}); err != nil {
		slog.Error("link: kunne ikke auditere avslag", "invite", inviteID, "error", err)
	}
}
