package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const rfc3339Z = "2006-01-02T15:04:05Z"

// signAccessAt lager et access-token med fast iat og valgfri sub, slik at testen
// kan plassere tokenet foran eller bak e-postepoken.
func signAccessAt(iss *token.Issuer, sub, email string, iat time.Time) string {
	return iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://test.example.com", Subject: sub, ID: "jti-epoch",
			Audience:  jwt.ClaimStrings{"veivakt"},
			IssuedAt:  jwt.NewNumericDate(iat),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		Email: email, TokenUse: "access",
	})
}

// reassign flytter sjafor@ (X) til ny adresse og oppretter Y på den gamle adressen
// på tidspunktet at. Returnerer X og Y.
func reassign(t *testing.T, f *audFixture, at time.Time) (x, y gen.User) {
	t.Helper()
	ctx := context.Background()
	x, err := f.q.GetUserByEmail(ctx, "sjafor@example.com")
	require.NoError(t, err)
	changed := at.UTC().Format(rfc3339Z)
	n, err := f.q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "ny@example.com", EmailChangedAt: &changed, ID: x.ID, OldEmail: "sjafor@example.com"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	y, err = f.q.CreateUser(ctx, gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: "sjafor@example.com", Roles: "user", Orgs: "x", CreatedAt: changed})
	require.NoError(t, err)
	return x, y
}

// K11: X sitt token for a@ skal ikke gi kode etter at a@ har gatt til Y.
func TestDispatchLevel0_EmailReassigned(t *testing.T) {
	f := newOIDCAudFixture(t)
	tok := signAccessAt(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-100*time.Second))
	reassign(t, f, time.Now().Add(-50*time.Second))

	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 reason=email_reassigned"}, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// Samme sekund som epoken godtas: en ny bruker som logger inn med en gang får kode.
func TestDispatchLevel0_NewUserSameSecond(t *testing.T) {
	f := newOIDCAudFixture(t)
	sec := time.Now().UTC().Truncate(time.Second)
	reassign(t, f, sec)
	w := f.dispatchOIDC(t, signAccessAt(f.iss, "sjafor@example.com", "sjafor@example.com", sec), "&service=veivakt")
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="), w.Header().Get("Location"))
	require.Equal(t, 1, f.codeCount(t))
	require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// sub_format=id: eksisterende avvisningsgrunn er uendret når X har faatt ny
// adresse (oppslaget paa public_id gir X, og e-posten i tokenet tilhorer ikke
// lenger X), og et nytt token med den nye adressen gir kode.
func TestDispatchLevel0_SubFormatID_Unchanged(t *testing.T) {
	f := newOIDCAudFixture(t)
	f.setSubFormat(t, "id")
	x, err := f.q.GetUserByEmail(context.Background(), "sjafor@example.com")
	require.NoError(t, err)

	old := signAccessAt(f.iss, x.PublicID, "sjafor@example.com", time.Now().Add(-100*time.Second))
	reassign(t, f, time.Now().Add(-50*time.Second))
	w := f.dispatchOIDC(t, old, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 sub_format=id"}, f.eventsOf(t, "dispatch_subject_mismatch"))

	w = f.dispatchOIDC(t, signAccessAt(f.iss, x.PublicID, "ny@example.com", time.Now()), "&service=veivakt")
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="), w.Header().Get("Location"))
	require.Equal(t, 1, f.codeCount(t))
}

// Epoken i id-grenen: X gaar a@ -> b@ -> a@. E-posten og public_id i det gamle
// tokenet stemmer igjen, men tokenet er utstedt for siste endring.
func TestDispatchLevel0_SubFormatID_EpochAfterRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newOIDCAudFixture(t)
	f.setSubFormat(t, "id")
	x, err := f.q.GetUserByEmail(ctx, "sjafor@example.com")
	require.NoError(t, err)
	tok := signAccessAt(f.iss, x.PublicID, "sjafor@example.com", time.Now().Add(-100*time.Second))

	c1 := time.Now().Add(-80 * time.Second).UTC().Format(rfc3339Z)
	c2 := time.Now().Add(-50 * time.Second).UTC().Format(rfc3339Z)
	n, err := f.q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "midt@example.com", EmailChangedAt: &c1, ID: x.ID, OldEmail: "sjafor@example.com"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = f.q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "sjafor@example.com", EmailChangedAt: &c2, ID: x.ID, OldEmail: "midt@example.com"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 reason=email_reassigned"}, f.eventsOf(t, "dispatch_subject_mismatch"))
}
