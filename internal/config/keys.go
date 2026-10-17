package config

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/zral/kauth-go/internal/token"
)

// readOptionalPEM leser PEM fra <prefix>_PEM (base64 eller rå PEM) eller
// <prefix>_PATH. found er false når ingen av dem er satt.
func readOptionalPEM(prefix string) (pemStr string, found bool, err error) {
	if os.Getenv(prefix+"_PEM") != "" && os.Getenv(prefix+"_PATH") != "" {
		return "", true, errors.New(prefix + "_PEM og " + prefix + "_PATH er begge satt: bruk én")
	}
	if v := os.Getenv(prefix + "_PEM"); v != "" {
		if b, derr := base64.StdEncoding.DecodeString(v); derr == nil {
			v = string(b)
		}
		return v, true, nil
	}
	if path := os.Getenv(prefix + "_PATH"); path != "" {
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return "", true, fmt.Errorf("kan ikke lese %s_PATH: %w", prefix, rerr)
		}
		return string(b), true, nil
	}
	return "", false, nil
}

// loadKeyRing leser kid-er og next/previous-nøklene og validerer hele ringen
// sammen med current (allerede lest i Load). Alle feil samles og navngir
// variabelen, slik at en feilkonfigurert rotasjon stopper oppstart i stedet
// for å gi tokens ingen kan verifisere.
func (c *Config) loadKeyRing() []string {
	var errs []string

	c.SigningKID = os.Getenv("KAUTH_SIGNING_KID")
	if c.SigningKID == "" {
		c.SigningKID = token.DefaultKID
	}
	if !token.ValidKID(c.SigningKID) {
		errs = append(errs, "ugyldig KAUTH_SIGNING_KID: må matche ^[A-Za-z0-9._-]{1,64}$")
	}
	if c.PrivateKey != nil && c.PrivateKey.N.BitLen() < token.MinRSABits {
		errs = append(errs, "KAUTH_PRIVATE_KEY: RSA-nøkkelen må være minst 2048 bit")
	}
	if c.PrivateKey != nil && c.PublicKey != nil &&
		(c.PrivateKey.N.Cmp(c.PublicKey.N) != 0 || c.PrivateKey.E != c.PublicKey.E) {
		errs = append(errs, "KAUTH_PUBLIC_KEY: offentlig nøkkel hører ikke til KAUTH_PRIVATE_KEY")
	}

	seen := map[string]string{c.SigningKID: "KAUTH_SIGNING_KID"}
	load := func(name string) (kid string, key *rsa.PublicKey) {
		pubVar := "KAUTH_" + name + "_PUBLIC_KEY"
		kidVar := "KAUTH_" + name + "_KID"
		kid = os.Getenv(kidVar)
		pemStr, found, err := readOptionalPEM(pubVar)
		if err != nil {
			errs = append(errs, err.Error())
		}
		switch {
		case found && kid == "":
			errs = append(errs, kidVar+" er påkrevd når "+pubVar+" er satt")
		case !found && kid != "":
			errs = append(errs, pubVar+"_PEM eller _PATH er påkrevd når "+kidVar+" er satt")
		}
		if kid != "" && !token.ValidKID(kid) {
			errs = append(errs, "ugyldig "+kidVar+": må matche ^[A-Za-z0-9._-]{1,64}$")
		} else if kid != "" {
			if other, dup := seen[kid]; dup {
				errs = append(errs, kidVar+" er lik "+other+": kid må være unik")
			}
			seen[kid] = kidVar
		}
		if !found || err != nil {
			return kid, nil
		}
		pub, perr := parseRSAPublicKey(pemStr)
		if perr != nil {
			errs = append(errs, "ugyldig "+pubVar+": "+perr.Error())
			return kid, nil
		}
		if pub.N.BitLen() < token.MinRSABits {
			errs = append(errs, pubVar+": RSA-nøkkelen må være minst 2048 bit")
			return kid, nil
		}
		return kid, pub
	}

	var k *rsa.PublicKey
	if c.NextKID, k = load("NEXT"); k != nil && c.NextKID != "" {
		c.NextKey = k
	}
	if c.PreviousKID, k = load("PREVIOUS"); k != nil && c.PreviousKID != "" {
		c.PreviousKey = k
	}
	// Ikke la en halvkonfigurert ring slippe videre som om ingenting var satt.
	if len(errs) > 0 {
		c.NextKey, c.PreviousKey = nil, nil
	}
	return errs
}
