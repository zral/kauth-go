package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// errIssueFailed markerer at access- eller refresh-token ikke lot seg utstede.
// Kalleren skiller den fra policyavslag og svarer i sin metodes format.
var errIssueFailed = errors.New("utstedelse feilet")

// errIssueRefresh kommer i tillegg når det var refresh-utstedelsen som feilet.
// Google svarer i dag med ulik tekst for de to stegene, og flyttingen skal
// ikke endre svaret.
var errIssueRefresh = errors.New("refresh-utstedelse feilet")

// errPolicyDenied markerer at tjenestens require_role/enforce_org avviste
// brukeren. Egen markør, slik at kalleren ikke tar en ukjent feil for et
// policyavslag.
var errPolicyDenied = errors.New("policyavslag")

// policyDeniedError bærer checkPolicy-feilen uendret: Error() er samme tekst
// som før (magic og passord auditerer den, passord svarer med den), mens
// errors.Is(err, errPolicyDenied) skiller avslaget fra andre feil.
type policyDeniedError struct{ cause error }

func (e *policyDeniedError) Error() string        { return e.cause.Error() }
func (e *policyDeniedError) Unwrap() error        { return e.cause }
func (e *policyDeniedError) Is(target error) bool { return target == errPolicyDenied }

// loginMethod beskriver det som skiller de fire innloggingsmetodene i
// utstedelsen: audit-type, metodenavn, loggprefiks og state-cookie som ryddes.
type loginMethod struct {
	AuditType   string
	AuthMethod  string
	LogPrefix   string
	StateCookie string // tom for magic link og passord
}

var (
	loginGoogle    = loginMethod{AuditType: "google_oidc_login", AuthMethod: "google", LogPrefix: "google", StateCookie: "oidc_state"}
	loginMicrosoft = loginMethod{AuditType: "microsoft_oidc_login", AuthMethod: "microsoft", LogPrefix: "microsoft", StateCookie: "ms_state"}
	loginMagic     = loginMethod{AuditType: "magic_link_login", AuthMethod: "magic_link", LogPrefix: "magic-link"}
	loginPassword  = loginMethod{AuditType: "login_success", AuthMethod: "password", LogPrefix: "password"}
)

// loginCompleter er det eneste stedet som utsteder tokens etter en vellykket
// autentisering, slik at policy og utstedelse ikke kan divergere mellom
// innloggingsmetodene.
type loginCompleter struct {
	queries *gen.Queries
	issuer  *token.Issuer
	refresh *token.RefreshService
	aud     *audit.Service
}

// complete håndhever tjenestepolicy, utsteder tokens og redirecter til
// /dispatch. Ved feil er ingenting skrevet til w, så kalleren velger svaret.
// Policyavslag returneres som errPolicyDenied med checkPolicy-teksten
// uendret i Error() (magic og passord auditerer den); utstedelsesfeil er
// wrappet med errIssueFailed. Alt annet er en ukjent feil, som kalleren
// svarer på som en utstedelsesfeil og aldri ekkoer til klienten.
func (c *loginCompleter) complete(w http.ResponseWriter, r *http.Request, svc *gen.Service, user gen.User, m loginMethod) error {
	ctx := r.Context()
	if err := checkPolicy(user, svc); err != nil {
		return &policyDeniedError{cause: err}
	}
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")
	at, err := c.issuer.IssueAccess(user, *svc)
	if err != nil {
		slog.Error(m.LogPrefix+": kunne ikke utstede token", "service", svc.ID, "error", err)
		return fmt.Errorf("%w: access-token: %v", errIssueFailed, err)
	}
	rt, err := c.refresh.Issue(ctx, user, *svc, ip, ua)
	if err != nil {
		slog.Error(m.LogPrefix+": kunne ikke utstede refresh-token", "service", svc.ID, "error", err)
		return fmt.Errorf("%w (%w): refresh-token: %v", errIssueFailed, errIssueRefresh, err)
	}
	setRefreshCookie(w, rt)
	if m.StateCookie != "" {
		clearCookie(w, m.StateCookie)
	}
	lastLogin := time.Now().UTC().Format(time.RFC3339)
	if err := c.queries.UpdateUserLastLogin(ctx, gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, ID: user.ID}); err != nil {
		slog.Error(m.LogPrefix+": kunne ikke oppdatere last_login", "email", user.Email, "error", err)
	}
	c.aud.Log(ctx, audit.Event{Type: m.AuditType, AuthMethod: m.AuthMethod, Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(at)+"&rt="+url.QueryEscape(rt)+"&service="+url.QueryEscape(svc.ID), http.StatusFound)
	return nil
}
