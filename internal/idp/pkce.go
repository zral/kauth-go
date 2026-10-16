package idp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// PKCEVerifier utleder code_verifier fra state i stedet for å lagre den:
// bare den som har state-hemmeligheten kan regne den ut, så verifieren
// trenger ingen cookie eller DB-rad og kan ikke leses av en angriper som
// bare ser state i URL-en. 32 byte HMAC gir 43 tegn i RFC 7636-alfabetet.
func PKCEVerifier(secret []byte, state string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("kauth-pkce\x00" + state))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
