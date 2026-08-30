package mail

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/i18n"
)

// buildMagicBody er den rene tekst-byggingen SendMagicLink gjør. Testet
// direkte fordi SendMagicLink ellers krever en SMTP-server.
func TestBuildMagicBody_ReplacesLink(t *testing.T) {
	link := "https://auth.spekto.live/magic-login/abc123?service=spekto"

	for _, locale := range []string{"en", "nb", "de"} {
		body := buildMagicBody(i18n.Get(locale), link)
		assert.Contains(t, body, link, "locale %s: lenken mangler i brødteksten", locale)
		assert.NotContains(t, body, "{link}", "locale %s: placeholder ikke erstattet", locale)
	}
}

func TestBuildMagicBody_LocalisedText(t *testing.T) {
	link := "https://example.test/x"
	assert.Contains(t, buildMagicBody(i18n.Get("de"), link), "Hallo!")
	assert.Contains(t, buildMagicBody(i18n.Get("nb"), link), "Hei!")
	assert.Contains(t, buildMagicBody(i18n.Get("en"), link), "Hello!")
}

func TestBuildMessage_UsesLocalisedSubject(t *testing.T) {
	msg := buildMessage("from@example.test", "Test", "to@example.test",
		i18n.Get("de").MailSubject, "brødtekst")
	require.True(t, strings.Contains(msg, "Subject: Ihr Anmeldelink"),
		"emnet skal være tysk, fikk:\n%s", msg)
}

// BACKLOG F21: en tjeneste med satt email_from_address men uten konfigurert
// KAUTH_BREVO_API_KEY skal feile tydelig i stedet for å stille falle tilbake
// til den globale SMTP-avsenderen (ville gjenskapt akkurat merkevare-mismatchen
// F21 løser). Ingen SMTP-mock her — feilen skal komme FØR noe forsøk på å sende.
func TestSendMagicLink_FromAddressWithoutBrevoKey_Errors(t *testing.T) {
	svc := New(config.Config{SMTPMock: false, BrevoAPIKey: ""})
	err := svc.SendMagicLink("bruker@example.test", "Spekto", "https://x.test/y", "nb", "noreply@spekto.live")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KAUTH_BREVO_API_KEY")
}

// Tom fromAddress skal ikke kreve Brevo-nøkkel i det hele tatt — dette er
// standardveien for tjenester uten egen avsenderadresse (uendret oppførsel).
func TestSendMagicLink_MockMode_IgnoresMissingBrevoKeyWhenNoFromAddress(t *testing.T) {
	svc := New(config.Config{SMTPMock: true, BrevoAPIKey: ""})
	err := svc.SendMagicLink("bruker@example.test", "Klarsyn", "https://x.test/y", "nb", "")
	require.NoError(t, err)
}
