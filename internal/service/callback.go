package service

import (
	"errors"
	"net/url"
	"strings"

	"github.com/zral/kauth-go/internal/db/gen"
)

var errCallback = errors.New("Callback-URL må være absolutte https-adresser, adskilt med komma.")

// NormalizeCallbackURLs validerer en kommaseparert callback-liste. Feilen er
// fast tekst uten verdien, så admin-skjemaet ikke ekkoer input.
func NormalizeCallbackURLs(raw string) (string, error) {
	parts := strings.Split(raw, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		parts[i] = p
		u, err := url.Parse(p)
		if p == "" || err != nil || !u.IsAbs() || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(p, "# \t\"'<>\\`") {
			return "", errCallback
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
		case "http":
			// http bare mot loopback, for lokal utvikling.
			if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
				return "", errCallback
			}
		default:
			return "", errCallback
		}
	}
	return strings.Join(parts, ","), nil
}

// CallbackURLs deler en lagret liste i trimmede, ikke-tomme oppføringer.
func CallbackURLs(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// PrimaryCallback er første registrerte callback, eller "" om ingen finnes.
func PrimaryCallback(svc *gen.Service) string {
	if c := CallbackURLs(svc.CallbackUrl); len(c) > 0 {
		return c[0]
	}
	return ""
}
