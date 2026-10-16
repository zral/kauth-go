package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// errNoAccount skiller «ingen konto» fra tekniske feil i resolveren.
var errNoAccount = errors.New("ingen konto")

// errUserConflict betyr at CreateUser feilet ved auto-registrering.
var errUserConflict = errors.New("bruker kunne ikke opprettes")

// errUserInactive: identiteten (eller e-posten) tilhører en deaktivert bruker.
// Avslag, aldri ny bruker: en deaktivert konto skal ikke gjenopplives ved innlogging.
var errUserInactive = errors.New("bruker er deaktivert")

// errLinkDenied: e-posten tilhører en bruker som allerede har en annen
// leverandøridentitet, og tjenesten har auto_link av.
var errLinkDenied = errors.New("kontoen er ikke koblet")

// errRetryResolve er intern: registreringen tapte et kappløp mot en samtidig
// førstegangsinnlogging, så oppslagene må kjøres på nytt.
var errRetryResolve = errors.New("samtidig registrering")

type resolveOutcome string

const (
	outcomeMatched    resolveOutcome = "matched"
	outcomeLinked     resolveOutcome = "linked"
	outcomeRegistered resolveOutcome = "registered"
)

// externalIdentity er det leverandøren har bekreftet. Issuer er kanonisk
// (PD6) og Subject er leverandørens stabile nøkkel (Google sub, Microsoft oid).
type externalIdentity struct{ Provider, Issuer, Subject, Email, Name string }

type linkPolicy struct {
	AutoLink, AutoRegister bool
	// EmailUntrusted er invertert i forhold til PD7 med vilje: nullverdien
	// betyr tillit fordi admin-stiens linkPolicy{} og alle eksisterende
	// kallere (Google, Microsoft, tester) er bygget på det. Bare generisk
	// OIDC setter feltet, og den går alltid via finishWithPolicy; finish uten
	// policy avviser oidc (fail-closed), så glemt policy aldri gir tillit.
	EmailUntrusted          bool
	DefaultRole, DefaultOrg string
}

// resolveMeta er bare audit-kontekst, ikke del av avgjørelsen.
type resolveMeta struct{ ServiceID, IP, UA string }

type identityResolver struct {
	db  *sql.DB
	q   *gen.Queries
	aud *audit.Service
}

func newIdentityResolver(sqlDB *sql.DB, aud *audit.Service) *identityResolver {
	return &identityResolver{db: sqlDB, q: gen.New(sqlDB), aud: aud}
}

// resolve finner brukeren bak en leverandørinnlogging: identitet, så
// verifisert e-post (kobling), så auto-registrering. Kalleren har allerede
// krevd bekreftet e-post (ADN 10) og gyldig subject.
func (r *identityResolver) resolve(ctx context.Context, ext externalIdentity, pol linkPolicy, meta resolveMeta) (gen.User, resolveOutcome, error) {
	u, _, out, err := r.resolveIdentity(ctx, ext, pol, meta)
	return u, out, err
}

// resolveIdentity er resolve pluss identitetsraden som ga treff. Admin-grenen
// trenger raden (id og admin_ok) for å avgjøre om akkurat denne kontoen er
// godkjent for admin. Ved registrering er raden tom: admin registrerer aldri.
func (r *identityResolver) resolveIdentity(ctx context.Context, ext externalIdentity, pol linkPolicy, meta resolveMeta) (gen.User, gen.UserIdentity, resolveOutcome, error) {
	ext.Email = NormalizeEmail(ext.Email)
	for attempt := 0; ; attempt++ {
		u, idn, out, err := r.resolveOnce(ctx, ext, pol, meta)
		if !errors.Is(err, errRetryResolve) {
			return u, idn, out, err
		}
		if attempt >= 1 {
			// Andre runde tapte også: typisk en deaktivert konto som eier e-posten.
			return gen.User{}, gen.UserIdentity{}, "", fmt.Errorf("%w: %v", errUserConflict, err)
		}
	}
}

func (r *identityResolver) resolveOnce(ctx context.Context, ext externalIdentity, pol linkPolicy, meta resolveMeta) (gen.User, gen.UserIdentity, resolveOutcome, error) {
	none := gen.UserIdentity{}
	// (1) Kjent identitet vinner over e-post: e-posten kan ha endret seg hos
	// leverandøren eller i users uten at personen er en annen.
	idn, err := r.q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: ext.Issuer, Subject: ext.Subject})
	if err == nil {
		return r.matched(ctx, idn, ext, meta)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return gen.User{}, none, "", err
	}

	// Uten e-posttillit er ukjent identitet et avslag: ingen kobling og ingen
	// registrering på en adresse leverandøren ikke har fått tillit for.
	if pol.EmailUntrusted {
		return gen.User{}, none, "", errNoAccount
	}

	// (2) Ukjent identitet: koble til brukeren som eier den bekreftede e-posten.
	user, err := r.q.GetActiveUserByEmail(ctx, ext.Email)
	if err == nil {
		return r.link(ctx, user, ext, pol, meta)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return gen.User{}, none, "", err
	}

	// (3) Ingen bruker.
	if !pol.AutoRegister {
		return gen.User{}, none, "", errNoAccount
	}
	u, out, err := r.register(ctx, ext, pol)
	return u, none, out, err
}

func (r *identityResolver) matched(ctx context.Context, idn gen.UserIdentity, ext externalIdentity, meta resolveMeta) (gen.User, gen.UserIdentity, resolveOutcome, error) {
	u, err := r.q.GetUserByID(ctx, idn.UserID)
	if err != nil {
		return gen.User{}, gen.UserIdentity{}, "", err
	}
	if u.DeactivatedAt != nil {
		return gen.User{}, gen.UserIdentity{}, "", errUserInactive
	}
	// Bare når leverandørens e-post har endret seg siden sist OG avviker fra
	// brukerens: ellers ville hver innlogging fra en omdøpt konto støye i loggen.
	changed := idn.Email == nil || *idn.Email != ext.Email
	if ext.Email != "" && ext.Email != u.Email && changed {
		r.audit(ctx, meta, "identity_email_mismatch", u.Email, true, "provider="+ext.Provider+" reason=provider_email_differs_from_user")
	}
	r.touch(ctx, r.q, idn.ID, ext.Email)
	return u, idn, outcomeMatched, nil
}

func (r *identityResolver) link(ctx context.Context, user gen.User, ext externalIdentity, pol linkPolicy, meta resolveMeta) (gen.User, gen.UserIdentity, resolveOutcome, error) {
	none := gen.UserIdentity{}
	now := time.Now().UTC().Format(time.RFC3339)
	email := ext.Email
	var n int64
	var err error
	// transition sier om koblingen skjedde via overgangsunntaket. Med auto_link
	// på er det bare informasjon til audit.
	transition := "1"
	if pol.AutoLink {
		var has bool
		has, err = r.q.HasIdentity(ctx, user.ID)
		if err != nil {
			return gen.User{}, none, "", err
		}
		if has {
			transition = "0"
		}
		n, err = r.q.InsertIdentity(ctx, gen.InsertIdentityParams{
			UserID: user.ID, Provider: ext.Provider, Issuer: ext.Issuer, Subject: ext.Subject,
			Email: &email, CreatedAt: now, LastUsedAt: &now,
		})
	} else {
		// Overgangsunntaket (A7): en bruker uten noen identitet er ikke «koblet
		// bort» ennå, så første leverandørkonto kobles også med auto_link av.
		// Vilkåret sjekkes bare i selve INSERT-en, slik at det er én sannhet og
		// to ulike kontoer ikke kan koble seg samtidig.
		n, err = r.q.LinkIdentityIfFirst(ctx, gen.LinkIdentityIfFirstParams{
			UserID: user.ID, Provider: ext.Provider, Issuer: ext.Issuer, Subject: ext.Subject,
			Email: &email, CreatedAt: now, LastUsedAt: &now, UserID_2: user.ID,
		})
	}
	if err != nil {
		return gen.User{}, none, "", err
	}
	if n == 0 {
		// Enten har brukeren alt en identitet (auto_link av), eller en samtidig
		// innlogging var først.
		idn, err := r.q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: ext.Issuer, Subject: ext.Subject})
		if errors.Is(err, sql.ErrNoRows) && !pol.AutoLink {
			return r.denyLink(ctx, user, ext, meta)
		}
		if err != nil {
			return gen.User{}, none, "", err
		}
		if !pol.AutoLink && idn.UserID != user.ID {
			return r.denyLink(ctx, user, ext, meta)
		}
		return r.matched(ctx, idn, ext, meta)
	}
	idn, err := r.q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: ext.Issuer, Subject: ext.Subject})
	if err != nil {
		return gen.User{}, none, "", err
	}
	r.audit(ctx, meta, "identity_linked", user.Email, true,
		"provider="+ext.Provider+" issuer="+ext.Issuer+" transition="+transition)
	return user, idn, outcomeLinked, nil
}

func (r *identityResolver) denyLink(ctx context.Context, user gen.User, ext externalIdentity, meta resolveMeta) (gen.User, gen.UserIdentity, resolveOutcome, error) {
	// En samtidig innlogging med samme konto kan ha koblet den siden første
	// oppslag: da er dette brukerens egen identitet, ikke en fremmed.
	if idn, err := r.q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: ext.Issuer, Subject: ext.Subject}); err == nil && idn.UserID == user.ID {
		return r.matched(ctx, idn, ext, meta)
	}
	r.audit(ctx, meta, "identity_link_denied", user.Email, false, "provider="+ext.Provider)
	return gen.User{}, gen.UserIdentity{}, "", errLinkDenied
}

func (r *identityResolver) register(ctx context.Context, ext externalIdentity, pol linkPolicy) (gen.User, resolveOutcome, error) {
	role := "user"
	if pol.DefaultRole != "" {
		role = pol.DefaultRole
	}
	// Feil her avbryter før noen rad skrives: en bruker uten ekte public_id
	// skal aldri opprettes.
	publicID, err := token.NewPublicID()
	if err != nil {
		return gen.User{}, "", fmt.Errorf("auto-registrering: %w", err)
	}
	var created gen.User
	// Bruker og identitet i én transaksjon: ellers kan en feil mellom de to
	// etterlate en bruker uten identitet som neste innlogging kobler til hvem som helst.
	err = token.RunInTx(ctx, r.db, func(q *gen.Queries) error {
		now := time.Now().UTC().Format(time.RFC3339)
		name := ext.Name
		u, err := q.CreateUser(ctx, gen.CreateUserParams{
			PublicID: publicID, Email: ext.Email, Name: &name, Roles: role, Orgs: pol.DefaultOrg, CreatedAt: now,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return errRetryResolve
			}
			return err
		}
		email := ext.Email
		n, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{
			UserID: u.ID, Provider: ext.Provider, Issuer: ext.Issuer, Subject: ext.Subject,
			Email: &email, CreatedAt: now, LastUsedAt: &now,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errRetryResolve
		}
		created = u
		return nil
	})
	if err != nil {
		return gen.User{}, "", err
	}
	return created, outcomeRegistered, nil
}

func (r *identityResolver) touch(ctx context.Context, q *gen.Queries, id int64, email string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := q.UpdateIdentitySeen(ctx, gen.UpdateIdentitySeenParams{Email: &email, LastUsedAt: &now, ID: id}); err != nil {
		// Sist-sett er informasjon, ikke vilkår for innlogging.
		slog.Warn("identitet: kunne ikke oppdatere last_used_at", "error", err)
	}
}

// audit skriver uten forespørselens avbrudd: hendelsen skal overleve at
// klienten kobler fra midt i innloggingen. Subject skrives aldri.
func (r *identityResolver) audit(ctx context.Context, meta resolveMeta, typ, email string, ok bool, details string) {
	if r.aud == nil {
		return
	}
	r.aud.Log(context.WithoutCancel(ctx), audit.Event{
		Type: typ, Email: email, ServiceID: meta.ServiceID, IP: meta.IP, UA: meta.UA, Success: ok, Details: details,
	})
}

// checkPolicy håndhever require_role og enforce_org for en allerede funnet bruker.
func checkPolicy(user gen.User, svc *gen.Service) error {
	if svc.RequireRole != nil && *svc.RequireRole != "" && !csvHasExact(user.Roles, *svc.RequireRole) {
		return fmt.Errorf("mangler rolle")
	}
	if svc.EnforceOrg == 1 && svc.DefaultOrg != nil && !csvHasExact(user.Orgs, *svc.DefaultOrg) {
		return fmt.Errorf("ikke autorisert")
	}
	return nil
}

// csvHasExact sjekker om en kommaseparert streng inneholder value som et
// eget felt — ikke som substring. "sysadmin" eller "admin-readonly" skal
// IKKE matche kravet "admin"; kun et felt der hele trimmede verdien er
// nøyaktig "admin" teller.
func csvHasExact(csv, value string) bool {
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == value {
			return true
		}
	}
	return false
}

// policyFor henter koblings- og registreringspolicy fra tjenesten.
func policyFor(svc *gen.Service) linkPolicy {
	p := linkPolicy{AutoLink: svc.AutoLink == 1, AutoRegister: svc.AutoRegister == 1}
	if svc.DefaultRole != nil {
		p.DefaultRole = *svc.DefaultRole
	}
	if svc.DefaultOrg != nil {
		p.DefaultOrg = *svc.DefaultOrg
	}
	return p
}
