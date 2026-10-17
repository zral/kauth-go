package service

import (
	"log/slog"
	"regexp"
	"strings"
)

// ClientSecretEnvRe er den eneste godkjente formen på en env-referanse for
// klienthemmeligheter. Den speiler CHECK i migrasjon 014; koden sjekker selv
// fordi en rad kan ha kommet inn forbi databasen, og et navn utenfor prefikset
// skal aldri slås opp (KAUTH_PRIVATE_KEY_PEM e.l.).
var ClientSecretEnvRe = regexp.MustCompile(`^KAUTH_SVC_[A-Z0-9_]+$`)

// TruncateName kutter et (potensielt ugyldig) variabelnavn til 64 byte for logg.
func TruncateName(s string) string {
	if len(s) > 64 {
		return strings.ToValidUTF8(s[:64], "")
	}
	return s
}

// CheckClientSecrets advarer ved oppstart (PD6) om tjenester med tom
// env-referanse og om klartekst-hemmeligheter som ligger igjen i databasen.
// Bare tjeneste-ID, metode og variabelnavn logges, aldri verdier. Advarsel
// fremfor feil: én feilkonfigurert tjeneste skal ikke ta ned de andre, og
// metoden avvises uansett per forespørsel.
func (r *Registry) CheckClientSecrets(getenv func(string) string) {
	r.mu.RLock()
	services := r.cache
	r.mu.RUnlock()
	for i := range services {
		s := &services[i]
		for _, m := range []struct {
			name           string
			envRef, column *string
		}{
			{"google", s.GoogleClientSecretEnv, s.GoogleClientSecret},
			{"microsoft", s.MicrosoftClientSecretEnv, s.MicrosoftClientSecret},
		} {
			if m.envRef != nil && *m.envRef != "" {
				if !ClientSecretEnvRe.MatchString(*m.envRef) || strings.TrimSpace(getenv(*m.envRef)) == "" {
					slog.Warn("tjeneste: klienthemmelighet mangler", "service", s.ID, "method", m.name, "env", TruncateName(*m.envRef))
				}
			}
			if m.column != nil && *m.column != "" {
				slog.Warn("tjeneste: klienthemmelighet i klartekst i DB", "service", s.ID, "method", m.name)
			}
		}
	}
}
