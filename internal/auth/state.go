package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// SignState lager en HMAC-SHA256-signert state for OIDC-flyten.
// payload = "serviceID:nonce"
// state   = base64RawURL( payload + "." + hmacHex )
func SignState(secret []byte, serviceID, nonce string) string {
	payload := serviceID + ":" + nonce
	mac := computeHMAC(secret, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + mac))
}

// VerifyState verifiserer en HMAC-signert state og returnerer serviceID.
// Bruker hmac.Equal (tidskonstant) mot timing-angrep.
func VerifyState(secret []byte, state string) (serviceID string, ok bool) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", false
	}
	raw := string(b)
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return "", false
	}
	payload, gotMAC := raw[:dot], raw[dot+1:]
	if !hmac.Equal([]byte(gotMAC), []byte(computeHMAC(secret, payload))) {
		return "", false
	}
	colon := strings.Index(payload, ":")
	if colon < 0 {
		return "", false
	}
	return payload[:colon], true
}

func computeHMAC(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
