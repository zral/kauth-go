package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewPublicID lager en UUID v4 (RFC 9562 §5.4) med små bokstaver fra
// crypto/rand. Verdien blir `sub` for tjenester med sub_format=id og er
// uforanderlig. Feil returneres uten fallback: en forutsigbar eller delvis
// verdi ville gjort identifikatoren verdiløs.
func NewPublicID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generere public_id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // versjon 4
	b[8] = b[8]&0x3f | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
