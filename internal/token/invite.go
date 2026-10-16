package token

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// LinkInviteTimeFormat er det eneste tidsformatet mot identity_link_invites.
// Kolonnene sammenlignes som tekst i SQL, så formatet må ha fast bredde og
// alltid være UTC.
const LinkInviteTimeFormat = "2006-01-02T15:04:05Z"

// FormatLinkInviteTime formaterer et tidspunkt for identity_link_invites.
func FormatLinkInviteTime(t time.Time) string {
	return t.UTC().Format(LinkInviteTimeFormat)
}

// LinkInviteTTL er hvor lenge en koblingsinvitasjon gjelder.
const LinkInviteTTL = 24 * time.Hour

// NewLinkInviteToken lager 32 tilfeldige byte som base64url uten padding
// (43 tegn) og SHA-256-hashen av dem. Bare hashen lagres.
func NewLinkInviteToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	return plain, HashOpaque(plain), nil
}
