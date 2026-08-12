package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/i18n"
)

type Service struct{ cfg config.Config }

func New(cfg config.Config) *Service { return &Service{cfg: cfg} }

// SendMagicLink sender innloggingslenken på valgt språk. Ukjent locale
// faller til engelsk via i18n.Get, så kalleren trenger ikke validere.
func (s *Service) SendMagicLink(to, fromName, linkURL, locale string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s | Språk: %s | Link: %s\n", to, fromName, locale, linkURL)
		return nil
	}
	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, t.MailSubject, buildMagicBody(t, linkURL))
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	if s.cfg.SMTPStartTLS {
		return sendSTARTTLS(addr, auth, s.cfg.SMTPHost, s.cfg.SMTPFrom, to, msg)
	}
	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg))
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
