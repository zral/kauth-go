package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
)

func TestEmailEpoch(t *testing.T) {
	p := func(s string) *string { return &s }
	iat := func(s string) *Claims {
		ts, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)
		return &Claims{RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(ts)}}
	}
	cases := []struct {
		name   string
		user   gen.User
		claims *Claims
		want   bool
	}{
		{"bare created_at, token etter", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, iat("2026-10-01T10:05:00Z"), true},
		{"bare created_at, token for", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, iat("2026-10-01T09:00:00Z"), false},
		{"email_changed_at senere enn created_at, token mellom", gen.User{CreatedAt: "2026-10-01T10:00:00Z", EmailChangedAt: p("2026-10-05T10:00:00Z")}, iat("2026-10-03T10:00:00Z"), false},
		{"email_changed_at senere enn created_at, token etter", gen.User{CreatedAt: "2026-10-01T10:00:00Z", EmailChangedAt: p("2026-10-05T10:00:00Z")}, iat("2026-10-06T10:00:00Z"), true},
		{"iat i samme sekund som epoken", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, iat("2026-10-01T10:00:00Z"), true},
		{"iat ett sekund for epoken", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, iat("2026-10-01T09:59:59Z"), false},
		{"epoke 23:59:59, iat 00:00:00 neste dogn", gen.User{CreatedAt: "2026-10-01T23:59:59Z"}, iat("2026-10-02T00:00:00Z"), true},
		{"sqlite datetime()-format", gen.User{CreatedAt: "2026-10-01 10:00:00"}, iat("2026-10-01T10:00:00Z"), true},
		{"sqlite datetime()-format, token for", gen.User{CreatedAt: "2026-10-01 10:00:00"}, iat("2026-10-01T09:59:59Z"), false},
		{"sopp i created_at", gen.User{CreatedAt: "i gaar"}, iat("2026-10-01T10:00:00Z"), false},
		{"tom created_at", gen.User{CreatedAt: ""}, iat("2026-10-01T10:00:00Z"), false},
		{"sopp i email_changed_at", gen.User{CreatedAt: "2026-10-01T10:00:00Z", EmailChangedAt: p("nei")}, iat("2026-10-06T10:00:00Z"), false},
		{"email_changed_at i fremtiden", gen.User{CreatedAt: "2026-10-01T10:00:00Z", EmailChangedAt: p("2099-01-01T00:00:00Z")}, iat("2026-10-06T10:00:00Z"), false},
		// Offset godtas ikke (fail-closed): formatet har bokstavelig Z.
		{"created_at med +02:00-offset", gen.User{CreatedAt: "2026-10-01T10:00:00+02:00"}, iat("2026-10-06T10:00:00Z"), false},
		// Go godtar brokdeler av sekund ved parsing; Unix() avrunder ned, saa
		// 10:00:00.9 tolkes som 10:00:00.
		{"brøksekunder, iat i samme sekund", gen.User{CreatedAt: "2026-10-01T10:00:00.9Z"}, iat("2026-10-01T10:00:00Z"), true},
		{"brøksekunder, iat ett sekund for", gen.User{CreatedAt: "2026-10-01T10:00:00.9Z"}, iat("2026-10-01T09:59:59Z"), false},
		{"iat mangler", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, &Claims{}, false},
		{"claims mangler", gen.User{CreatedAt: "2026-10-01T10:00:00Z"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, IssuedAfterEmailEpoch(c.claims, c.user))
		})
	}
}

func TestParseEpoch_Formats(t *testing.T) {
	a, err := ParseEpoch("2026-10-01T10:00:00Z")
	require.NoError(t, err)
	b, err := ParseEpoch("2026-10-01 10:00:00")
	require.NoError(t, err)
	assert.True(t, a.Equal(b))
	_, err = ParseEpoch("")
	assert.Error(t, err)
}
