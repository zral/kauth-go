package auth

import (
	"regexp"
	"strings"
	"testing"
)

var (
	fuzzTokenRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	fuzzPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_./%-]*$`)
	fuzzSeps     = []string{"/", "//", "/./", "///", "/././", "/.//"}
	fuzzMarkers  = []string{"magic-login", "link"}
)

// FuzzMaskPath bygger stier med et tilfeldig token etter magic-login/link i
// varierende case, med //, /./ og .. foran, og sjekker bare at tokenet aldri
// står i utdataene. Fasiten er altså ikke en kopi av maskPath.
func FuzzMaskPath(f *testing.F) {
	f.Add("", uint8(0), uint8(0), "SECRETTOKEN")
	f.Add("/", uint8(1), uint8(0), "abcDEF12_-xyz")
	f.Add("/a/..", uint8(2), uint8(5), "0123456789ab")
	f.Add("/./x", uint8(3), uint8(255), "tok_en-value")
	f.Add("..", uint8(4), uint8(1), "Zz9Zz9Zz9Zz9")
	f.Add("/api/../x/", uint8(5), uint8(170), "AAAAAAAAAAAA")

	f.Fuzz(func(t *testing.T, prefix string, sepIdx, caseMask uint8, tok string) {
		if !fuzzTokenRe.MatchString(tok) || !fuzzPrefixRe.MatchString(prefix) {
			return
		}
		marker := fuzzMarkers[int(caseMask)%len(fuzzMarkers)]
		b := []byte(marker)
		for i := range b {
			if caseMask>>(uint(i)%8)&1 == 1 {
				b[i] = []byte(strings.ToUpper(string(b[i])))[0]
			}
		}
		sep := fuzzSeps[int(sepIdx)%len(fuzzSeps)]
		// Tokenet må være unikt i det vi selv bygger, ellers er funn i
		// utdataene forventet (f.eks. token "magic-login").
		if strings.Contains(strings.ToLower(prefix+marker+sep+"***"), strings.ToLower(tok)) {
			return
		}
		p := prefix + "/" + string(b) + sep + tok
		for _, in := range []string{p, p + "/rest/" + tok[:4], strings.TrimPrefix(p, "/")} {
			if out := maskPath(in); strings.Contains(out, tok) {
				t.Fatalf("token lekker: maskPath(%q) = %q", in, out)
			}
		}
	})
}
