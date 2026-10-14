package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/i18n"
)

type Service struct{ cfg config.Config }

func New(cfg config.Config) *Service { return &Service{cfg: cfg} }

// SendMagicLink sender innloggingslenken på valgt språk. Ukjent locale
// faller til engelsk via i18n.Get, så kalleren trenger ikke validere.
//
// fromAddress er tjenestens `email_from_address` (BACKLOG F21) — tom streng
// betyr ingen override, og sendingen går uendret via rå SMTP med den globale
// KAUTH_SMTP_FROM (samme oppførsel som før denne feltet fantes). En satt
// verdi sendes via Brevo, siden det feltet kun skal populeres for tjenester
// på et domene som faktisk er Brevo-verifisert (se doc/BACKLOG.md F21) —
// rå SMTP/Resend er ikke verifisert for de domenene.
func (s *Service) SendMagicLink(to, fromName, linkURL, locale, fromAddress string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s (%s) | Språk: %s | Link: %s\n", to, fromName, fromAddress, locale, linkURL)
		return nil
	}
	body := buildMagicBody(t, linkURL)

	if fromAddress != "" {
		if s.cfg.BrevoAPIKey == "" {
			return fmt.Errorf("email_from_address=%q satt men KAUTH_BREVO_API_KEY mangler", fromAddress)
		}
		return sendBrevo(s.cfg.BrevoAPIKey, fromAddress, fromName, to, t.MailSubject, body)
	}

	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, t.MailSubject, body)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	return sendSMTP(addr, s.cfg.SMTPHost, auth, s.cfg.SMTPFrom, to, msg, s.cfg.SMTPStartTLS)
}

// sendBrevo sender via Brevos transaksjons-e-post-API (samme endepunkt og
// mønster som POV-appens src/lib/server/mail/transport.ts). htmlContent er
// påkrevd av API-et uten templateId — bygges her som en minimal HTML-innpakning
// av samme brødtekst, med textContent satt til originalen slik at e-postklienter
// som foretrekker ren tekst viser identisk innhold som før Brevo-bytte.
func sendBrevo(apiKey, fromAddress, fromName, to, subject, plainBody string) error {
	htmlBody := "<div style=\"font-family:sans-serif;white-space:pre-wrap\">" + html.EscapeString(plainBody) + "</div>"
	payload := map[string]any{
		"sender":      map[string]string{"name": fromName, "email": fromAddress},
		"to":          []map[string]string{{"email": to}},
		"subject":     subject,
		"htmlContent": htmlBody,
		"textContent": plainBody,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("brevo: json marshal: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "https://api.brevo.com/v3/smtp/email", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("brevo: bygg request: %w", err)
	}
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("brevo: request feilet: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		return fmt.Errorf("brevo: uventet status %d", res.StatusCode)
	}
	return nil
}

// buildMagicBody setter lenken inn i den oversatte brødteksten.
// Navngitt placeholder framfor %s fordi go vet flagger fmt.Sprintf med
// ikke-konstant format-streng.
func buildMagicBody(t i18n.Strings, linkURL string) string {
	return strings.ReplaceAll(t.MailBody, "{link}", linkURL)
}

// Tidsgrenser for rå SMTP. Pakkevariabler slik at testene kan korte dem ned.
// Uten dem henger et stille eller tregt relé en innloggingsforespørsel (og
// goroutinen bak) på ubestemt tid.
var (
	dialTimeout    = 10 * time.Second
	sessionTimeout = 30 * time.Second
)

// dialSMTP kobler til med tidsgrense og setter en absolutt frist for hele
// SMTP-samtalen før banneret leses, siden smtp.Dial ikke har noen av delene.
func dialSMTP(addr, host string) (*smtp.Client, error) {
	conn, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(sessionTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp banner: %w", err)
	}
	return c, nil
}

// sendSMTP er felles sendrutine for begge grenene. requireTLS=true (KAUTH_SMTP_STARTTLS)
// feiler hvis serveren ikke tilbyr STARTTLS; ellers oppgraderes opportunistisk
// slik standardbibliotekets SendMail gjorde. PlainAuth nekter selv ukryptert auth mot ikke-localhost.
func sendSMTP(addr, host string, auth smtp.Auth, from, to, msg string, requireTLS bool) error {
	c, err := dialSMTP(addr, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else if requireTLS {
		return fmt.Errorf("starttls: serveren tilbyr ikke STARTTLS")
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp: serveren støtter ikke AUTH")
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		wc.Close()
		return fmt.Errorf("smtp data: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	return c.Quit()
}

func buildMessage(from, fromName, to, subject, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", to))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	sb.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	sb.WriteString(body)
	return sb.String()
}
