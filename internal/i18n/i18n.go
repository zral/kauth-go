// Package i18n holder oversettelsene for de bruker-vendte login-sidene og
// magic-link-e-posten. Bevisst uten avhengigheter utover stdlib:
// Accept-Language-parsing er ~40 linjer, og det er billigere enn å dra
// golang.org/x/text inn i en binær som skal være liten og CGO-fri.
package i18n

// Fallback brukes når nettleseren ikke ber om et språk vi har.
const Fallback = "en"

// Strings er alle oversatte tekster for én locale.
//
// Flat struct framfor map[string]string er et bevisst valg: en skrivefeil i
// en template ({{.T.Feilnavn}}) gir render-feil, mens et map-oppslag ville
// gitt en stille tom streng i prod.
type Strings struct {
	// Felles for begge sidene
	SignIn              string
	EmailPlaceholder    string
	PasswordPlaceholder string
	Or                  string

	// login.html
	ContinueWithGoogle    string
	ContinueWithMicrosoft string
	SignInWithEmailLink   string

	// magic-login.html
	MagicPageTitle  string
	MagicSubmit     string
	MagicSending    string
	MagicCheckInbox string
	// MagicSentToBefore og MagicSentToAfter omslutter e-postadressen som
	// JS setter inn i <span id="confirm-email">. Delt i to fordi tysk
	// plasserer verbet etter objektet: "… an <e-post> gesendt."
	MagicSentToBefore string
	MagicSentToAfter  string
	MagicValidMinutes string
	BackToSignIn      string

	// Feilkoder fra ?error=
	ErrAccessDenied    string
	ErrInvalidRedirect string
	ErrExpiredLink     string
	ErrTooManyRequests string

	// Magic-link-e-post. MailBody har nøyaktig én {link}-placeholder.
	MailSubject string
	MailBody    string
}

// Get returnerer katalogen for locale, eller Fallback-katalogen ved ukjent
// locale. Kallere trenger derfor ikke sjekke om locale er støttet.
func Get(locale string) Strings {
	if s, ok := catalog[locale]; ok {
		return s
	}
	return catalog[Fallback]
}
