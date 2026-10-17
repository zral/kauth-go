package auth

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

var errClientSecretMissing = errors.New("klienthemmelighet mangler")

// secretWarned begrenser loggingen til én linje per tjeneste og metode per
// 5 minutter, så en feilkonfigurert tjeneste ikke kan fylle journald via
// innloggingsforsøk.
var secretWarned sync.Map

const secretWarnEvery = 5 * time.Minute

func warnSecretMissing(svcID, method, name string) {
	key := svcID + "\x00" + method
	now := time.Now()
	if t, ok := secretWarned.Load(key); ok && now.Sub(t.(time.Time)) < secretWarnEvery {
		return
	}
	secretWarned.Store(key, now)
	slog.Warn("tjeneste: klienthemmelighet mangler", "service", svcID, "method", method, "env", service.TruncateName(name))
}

// resolveClientSecret slår opp Google/Microsoft-klienthemmeligheten for én
// tjeneste. Rekkefølge:
//  1. <metode>_client_secret_env satt: verdien av den miljøvariabelen. Er den
//     tom, feiler metoden for tjenesten. Det finnes aldri fallback til kolonnen
//     eller den globale hemmeligheten: en tjeneste som har bedt om sin egen
//     hemmelighet skal ikke stille autentisere som en annen klient.
//  2. kolonnen <metode>_client_secret hvis ikke tom (klartekst fra før 017).
//  3. den globale hemmeligheten fra konfigurasjonen.
//
// Verdien logges aldri; feilloggen har bare tjeneste, metode og variabelnavn.
// getenv er injiserbar for tester; nil betyr os.Getenv.
func resolveClientSecret(getenv func(string) string, svc *gen.Service, method string, envRef, column *string, global string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if envRef != nil && *envRef != "" {
		// Ugyldig navn behandles som feilet referanse uten å røre miljøet.
		if service.ClientSecretEnvRe.MatchString(*envRef) {
			if v := strings.TrimSpace(getenv(*envRef)); v != "" {
				return v, nil
			}
		}
		warnSecretMissing(svc.ID, method, *envRef)
		return "", errClientSecretMissing
	}
	if column != nil && *column != "" {
		return *column, nil
	}
	return global, nil
}
