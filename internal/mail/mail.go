package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
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
	if s.cfg.SMTPStartTLS {
		return sendSTARTTLS(addr, auth, s.cfg.SMTPHost, s.cfg.SMTPFrom, to, msg)
	}
	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg))
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

func sendSTARTTLS(addr string, auth smtp.Auth, host, from, to, msg string) error {
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer conn.Close()
	if err := conn.StartTLS(&tls.Config{ServerName: host}); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if err := conn.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := conn.Mail(from); err != nil {
		return err
	}
	if err := conn.Rcpt(to); err != nil {
		return err
	}
	wc, err := conn.Data()
	if err != nil {
		return err
	}
	defer wc.Close()
	_, err = fmt.Fprint(wc, msg)
	return err
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
