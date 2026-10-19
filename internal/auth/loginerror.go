package auth

import (
	"net/http"
	"net/url"
)

// loginErrorCode er en lukket mengde: typen gjør det umulig å sende
// IdP-/bibliotekstekst eller brukerstyrt innhold som ?error=-verdi.
type loginErrorCode string

const (
	// errCodeLoginFailed dekker alle tekniske feil i OIDC-flyten. Årsaken
	// hører hjemme i loggen, ikke i responsen.
	errCodeLoginFailed loginErrorCode = "login_failed"
	// errCodeAccessDenied brukes både for «ingen konto» og policybrudd, så de
	// ikke kan skilles fra hverandre utenfra.
	errCodeAccessDenied loginErrorCode = "access_denied"
	// errCodeAccountNotLinked: e-posten tilhører en bruker som allerede er koblet
	// til en annen leverandørkonto, og tjenesten har auto_link av (011).
	errCodeAccountNotLinked loginErrorCode = "account_not_linked"
	// errCodeInvalidRedirect: redirect_uri ble avvist. Malen og i18n kjenner den.
	errCodeInvalidRedirect loginErrorCode = "invalid_redirect"
)

// knownLoginError sier om s er en av kauths egne feilkoder. Alt annet er
// brukerstyrt fritekst som ikke skal speiles videre i lenker.
func knownLoginError(s string) bool {
	switch loginErrorCode(s) {
	case errCodeLoginFailed, errCodeAccessDenied, errCodeAccountNotLinked, errCodeInvalidRedirect:
		return true
	}
	return false
}

// redirectLoginError sender brukeren tilbake til /login med en kjent feilkode.
// Den starter aldri IdP-en på nytt. Tom svcID utelater service-parameteren
// (f.eks. når staten er ugyldig og tjenesten dermed ikke er til å stole på).
func redirectLoginError(w http.ResponseWriter, r *http.Request, svcID string, code loginErrorCode) {
	q := url.Values{}
	q.Set("error", string(code))
	if svcID != "" {
		q.Set("service", svcID)
	}
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusSeeOther)
}

// redirectAdminLoginError sender admin tilbake til /admin/login med en fast
// feilkode som ikke avslører hvorfor innloggingen feilet.
func redirectAdminLoginError(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/login?err=ingen_tilgang", http.StatusSeeOther)
}
