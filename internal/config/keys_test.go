package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pubPEM(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func genRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return k
}

func TestLoad_KeyRing(t *testing.T) {
	next, prev := genRSA(t, 2048), genRSA(t, 2048)
	weak := genRSA(t, 1024)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	cases := []struct {
		name    string
		env     map[string]string
		wantErr string // tom = ok
	}{
		{"default uten ny konfig", nil, ""},
		{"egen signing-kid", map[string]string{"KAUTH_SIGNING_KID": "k_2.a-b"}, ""},
		{"next og previous som base64-PEM", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_KID": "n",
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &prev.PublicKey)), "KAUTH_PREVIOUS_KID": "p"}, ""},
		{"next som rå PEM", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": pubPEM(t, &next.PublicKey), "KAUTH_NEXT_KID": "n"}, ""},
		{"next uten kid", map[string]string{"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey))}, "KAUTH_NEXT_KID er påkrevd"},
		{"previous uten kid", map[string]string{"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &prev.PublicKey))}, "KAUTH_PREVIOUS_KID er påkrevd"},
		{"next-kid uten nøkkel", map[string]string{"KAUTH_NEXT_KID": "n"}, "KAUTH_NEXT_PUBLIC_KEY"},
		{"previous-kid uten nøkkel", map[string]string{"KAUTH_PREVIOUS_KID": "p"}, "KAUTH_PREVIOUS_PUBLIC_KEY"},
		{"ugyldig signing-kid", map[string]string{"KAUTH_SIGNING_KID": "a b"}, "KAUTH_SIGNING_KID"},
		{"for lang signing-kid", map[string]string{"KAUTH_SIGNING_KID": strings.Repeat("a", 65)}, "KAUTH_SIGNING_KID"},
		{"ugyldig next-kid", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_KID": "ø"}, "KAUTH_NEXT_KID"},
		{"next-kid lik current", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_KID": "kauth-1"}, "KAUTH_NEXT_KID er lik KAUTH_SIGNING_KID"},
		{"previous-kid lik next", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_KID": "x",
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &prev.PublicKey)), "KAUTH_PREVIOUS_KID": "x"}, "KAUTH_PREVIOUS_KID er lik KAUTH_NEXT_KID"},
		{"svak next", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &weak.PublicKey)), "KAUTH_NEXT_KID": "n"}, "KAUTH_NEXT_PUBLIC_KEY: RSA-nøkkelen må være minst 2048"},
		{"svak previous", map[string]string{
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &weak.PublicKey)), "KAUTH_PREVIOUS_KID": "p"}, "KAUTH_PREVIOUS_PUBLIC_KEY: RSA-nøkkelen må være minst 2048"},
		{"ugyldig PEM i next", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64("ikke pem"), "KAUTH_NEXT_KID": "n"}, "ugyldig KAUTH_NEXT_PUBLIC_KEY"},
		{"manglende fil for previous", map[string]string{
			"KAUTH_PREVIOUS_PUBLIC_KEY_PATH": "/finnes/ikke.pem", "KAUTH_PREVIOUS_KID": "p"}, "KAUTH_PREVIOUS_PUBLIC_KEY_PATH"},
		{"offentlig current tilhører ikke privat", map[string]string{
			"KAUTH_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey))}, "KAUTH_PUBLIC_KEY: offentlig nøkkel hører ikke til"},
		{"next både PEM og PATH", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_PUBLIC_KEY_PATH": "/x.pem", "KAUTH_NEXT_KID": "n"}, "KAUTH_NEXT_PUBLIC_KEY_PEM og KAUTH_NEXT_PUBLIC_KEY_PATH"},
		{"previous både PEM og PATH", map[string]string{
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &prev.PublicKey)), "KAUTH_PREVIOUS_PUBLIC_KEY_PATH": "/x.pem", "KAUTH_PREVIOUS_KID": "p"}, "KAUTH_PREVIOUS_PUBLIC_KEY_PEM og KAUTH_PREVIOUS_PUBLIC_KEY_PATH"},
		{"current privat både PEM og PATH", map[string]string{"KAUTH_PRIVATE_KEY_PATH": "/x.pem"}, "KAUTH_PRIVATE_KEY_PEM og KAUTH_PRIVATE_KEY_PATH"},
		{"current offentlig både PEM og PATH", map[string]string{"KAUTH_PUBLIC_KEY_PATH": "/x.pem"}, "KAUTH_PUBLIC_KEY_PEM og KAUTH_PUBLIC_KEY_PATH"},
		{"next lik current", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": "$CURRENT", "KAUTH_NEXT_KID": "n"}, "KAUTH_NEXT_PUBLIC_KEY har samme nøkkelmateriale"},
		{"previous lik current", map[string]string{
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": "$CURRENT", "KAUTH_PREVIOUS_KID": "p"}, "KAUTH_PREVIOUS_PUBLIC_KEY har samme nøkkelmateriale"},
		{"next lik previous", map[string]string{
			"KAUTH_NEXT_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_NEXT_KID": "n",
			"KAUTH_PREVIOUS_PUBLIC_KEY_PEM": b64(pubPEM(t, &next.PublicKey)), "KAUTH_PREVIOUS_KID": "p"}, "KAUTH_NEXT_PUBLIC_KEY og KAUTH_PREVIOUS_PUBLIC_KEY har samme"},
		{"svak current", map[string]string{
			"KAUTH_PRIVATE_KEY_PEM": b64(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))),
			"KAUTH_PUBLIC_KEY_PEM":  b64(pubPEM(t, &weak.PublicKey))}, "KAUTH_PRIVATE_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setMinimalEnv(t)
			for k, v := range tc.env {
				if v == "$CURRENT" {
					v = os.Getenv("KAUTH_PUBLIC_KEY_PEM")
				}
				t.Setenv(k, v)
			}
			c, err := Load()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, c.SigningKID)
		})
	}
}

func TestLoad_KeyRingValues(t *testing.T) {
	setMinimalEnv(t)
	next, prev := genRSA(t, 2048), genRSA(t, 2048)
	dir := t.TempDir()
	path := filepath.Join(dir, "prev.pem")
	require.NoError(t, os.WriteFile(path, []byte(pubPEM(t, &prev.PublicKey)), 0o600))
	t.Setenv("KAUTH_SIGNING_KID", "kauth-5")
	t.Setenv("KAUTH_NEXT_PUBLIC_KEY_PEM", pubPEM(t, &next.PublicKey))
	t.Setenv("KAUTH_NEXT_KID", "kauth-6")
	t.Setenv("KAUTH_PREVIOUS_PUBLIC_KEY_PATH", path)
	t.Setenv("KAUTH_PREVIOUS_KID", "kauth-4")

	c, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "kauth-5", c.SigningKID)
	assert.Equal(t, "kauth-6", c.NextKID)
	assert.Equal(t, "kauth-4", c.PreviousKID)
	assert.Zero(t, c.NextKey.N.Cmp(next.N))
	assert.Zero(t, c.PreviousKey.N.Cmp(prev.N))

}

func TestLoad_KeyRingDefaults(t *testing.T) {
	setMinimalEnv(t)
	c, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "kauth-1", c.SigningKID)
	assert.Nil(t, c.NextKey)
	assert.Nil(t, c.PreviousKey)
}
