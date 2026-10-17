package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
)

// MinRSABits er nedre grense for alle nøkler i ringen. Samme grense håndheves
// i config; her er den forsvar i dybden for kallere som bygger ringen selv.
const MinRSABits = 2048

// DefaultKID er nøkkel-ID-en når KAUTH_SIGNING_KID ikke er satt.
const DefaultKID = "kauth-1"

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidKID sier om kid har lovlig format.
func ValidKID(kid string) bool { return kidPattern.MatchString(kid) }

// SigningKey er nøkkelen kauth signerer med og verifiserer mot.
type SigningKey struct {
	KID     string
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// PublicKey er en nøkkel som bare publiseres (next) eller bare godtas ved
// verifisering (previous).
type PublicKey struct {
	KID    string
	Public *rsa.PublicKey
}

// KeyRing er nøkkelringen ved rotasjon: Current signerer, Next er publisert i
// JWKS før den tas i bruk (klienter rekker å hente den), Previous godtas
// fortsatt ved verifisering mens gamle tokens løper ut. Next godtas aldri i
// Verify, så en nøkkel som ikke er tatt i bruk ikke kan utstede gyldige tokens.
type KeyRing struct {
	Current  SigningKey
	Next     *PublicKey
	Previous *PublicKey
}

// NewSingleKeyRing lager en ring med bare current og kid «kauth-1».
func NewSingleKeyRing(priv *rsa.PrivateKey) KeyRing {
	return KeyRing{Current: SigningKey{KID: DefaultKID, Private: priv, Public: &priv.PublicKey}}
}

func checkPub(name, kid string, pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil {
		return fmt.Errorf("%s: offentlig nøkkel mangler", name)
	}
	if !ValidKID(kid) {
		return fmt.Errorf("%s: ugyldig kid %q", name, kid)
	}
	if pub.N.BitLen() < MinRSABits {
		return fmt.Errorf("%s: RSA-nøkkelen er under %d bit", name, MinRSABits)
	}
	return nil
}

// Validate sjekker format, styrke, unike kid-er og at current-nøklene hører sammen.
func (r KeyRing) Validate() error {
	c := r.Current
	if c.Private == nil {
		return errors.New("current: privat nøkkel mangler")
	}
	if err := checkPub("current", c.KID, c.Public); err != nil {
		return err
	}
	if c.Private.N == nil || c.Private.N.Cmp(c.Public.N) != 0 || c.Private.E != c.Public.E {
		return errors.New("current: offentlig nøkkel hører ikke til den private")
	}
	seen := map[string]bool{c.KID: true}
	for _, e := range []struct {
		name string
		k    *PublicKey
	}{{"next", r.Next}, {"previous", r.Previous}} {
		if e.k == nil {
			continue
		}
		if err := checkPub(e.name, e.k.KID, e.k.Public); err != nil {
			return err
		}
		if seen[e.k.KID] {
			return fmt.Errorf("%s: kid %q er ikke unik", e.name, e.k.KID)
		}
		seen[e.k.KID] = true
	}
	return nil
}
