package auth

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	fuzzSecretA = []byte("fuzz-secret-A-32bytes-padded-xx!")
	fuzzSecretB = []byte("fuzz-secret-B-32bytes-padded-xx!")
	fuzzHexRe   = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
)

func fuzzFixClock() func() {
	orig := now
	now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return func() { now = orig }
}

// FuzzParseState: vilkårlig input og vilkårlig signert payload.
// Egenskaper: ingen panic; B-hemmelighet godtar aldri A-state; et godtatt
// resultat har konsistente typer (admin, github, idp og link blandes ikke).
func FuzzParseState(f *testing.F) {
	f.Add("")
	f.Add("!!!")
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:admin"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:idp=gh"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:idp=gh:link=7"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:admin:idp=gh"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:idp=gh:link=+7"))
	f.Add(signStatePayload(fuzzSecretA, "a:b:c:d:1800000000:admin"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:github"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:github:admin"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:idp=gh:github"))
	f.Add(signStatePayload(fuzzSecretA, "svc:abc:1800000000:idp=gh:link=7:github"))

	f.Fuzz(func(t *testing.T, s string) {
		restore := fuzzFixClock()
		defer restore()

		// Rå input, og samme tekst som signert payload.
		for _, state := range []string{s, signStatePayload(fuzzSecretA, s)} {
			c, ok := parseState(fuzzSecretA, state)
			if _, okB := parseState(fuzzSecretB, state); okB {
				t.Fatalf("state signert med A godtatt med B: %q", state)
			}
			if !ok {
				if _, vok := VerifyState(fuzzSecretA, state); vok {
					t.Fatalf("VerifyState godtok det parseState avviste: %q", state)
				}
				continue
			}
			if c.GitHub && (c.Admin || c.IDP != "" || c.Link != 0) {
				t.Fatalf("github blandet med admin/idp/link: %+v", c)
			}
			if c.Admin && (c.IDP != "" || c.Link != 0) {
				t.Fatalf("admin blandet med idp/link: %+v", c)
			}
			if c.Link != 0 && c.IDP == "" {
				t.Fatalf("link uten idp: %+v", c)
			}
			if c.Link < 0 {
				t.Fatalf("negativ link: %+v", c)
			}
			vid, vok := VerifyState(fuzzSecretA, state)
			plain := !c.Admin && !c.GitHub && c.IDP == "" && c.Link == 0
			if vok != plain || (vok && vid != c.ServiceID) {
				t.Fatalf("VerifyState (%v, %q) uten samsvar mot claims %+v", vok, vid, c)
			}
			if state != s {
				// Payloaden skal kunne bygges opp igjen fra claims.
				base := c.ServiceID + ":" + c.Nonce + ":"
				if !strings.HasPrefix(s, base) {
					t.Fatalf("claims %+v passer ikke payload %q", c, s)
				}
			}
		}
	})
}

// FuzzStateRoundTrip: state laget av signeringsfunksjonene gir nøyaktig sine
// claims med riktig hemmelighet, aldri noe med feil hemmelighet, og én endret
// byte gir avvisning eller identiske claims.
func FuzzStateRoundTrip(f *testing.F) {
	f.Add("spekto", "abc123", "gh", int64(7), uint16(0), byte(1))
	f.Add("a:b", "ff", "x-1", int64(1), uint16(5), byte(0x20))
	f.Add("svc:admin", "00", "gh", int64(9), uint16(40), byte(0xff))
	f.Add("svc.idp=x", "00", "g", int64(1<<62), uint16(3), byte(7))

	f.Fuzz(func(t *testing.T, svc, nonce, slug string, inv int64, pos uint16, delta byte) {
		restore := fuzzFixClock()
		defer restore()
		if !fuzzHexRe.MatchString(nonce) || !stateSlugRe.MatchString(slug) || inv <= 0 {
			return
		}
		type kase struct {
			state string
			want  stateClaims
		}
		cases := []kase{
			{SignState(fuzzSecretA, svc, nonce), stateClaims{ServiceID: svc, Nonce: nonce}},
			{signAdminState(fuzzSecretA, svc, nonce), stateClaims{ServiceID: svc, Nonce: nonce, Admin: true}},
			{signIDPState(fuzzSecretA, svc, nonce, slug), stateClaims{ServiceID: svc, Nonce: nonce, IDP: slug}},
			{signLinkState(fuzzSecretA, svc, nonce, slug, inv), stateClaims{ServiceID: svc, Nonce: nonce, IDP: slug, Link: inv}},
			{signGitHubState(fuzzSecretA, svc, nonce), stateClaims{ServiceID: svc, Nonce: nonce, GitHub: true}},
		}
		for i, k := range cases {
			got, ok := parseState(fuzzSecretA, k.state)
			if !ok || got != k.want {
				t.Fatalf("variant %d: runde tur ga (%+v, %v), forventet %+v", i, got, ok, k.want)
			}
			if _, ok := parseState(fuzzSecretB, k.state); ok {
				t.Fatalf("variant %d: godtatt med feil hemmelighet", i)
			}
			vid, vok := VerifyState(fuzzSecretA, k.state)
			if vok != (i == 0) || (vok && vid != svc) {
				t.Fatalf("variant %d: VerifyState (%v, %q)", i, vok, vid)
			}

			raw := []byte(k.state)
			if delta != 0 {
				raw[int(pos)%len(raw)] ^= delta
				if m, ok := parseState(fuzzSecretA, string(raw)); ok && m != k.want {
					t.Fatalf("variant %d: endret byte ga andre claims %+v (var %+v)", i, m, k.want)
				}
			}
			// Dekodet endring: vipp én byte i selve payload/MAC-en.
			b, err := base64.RawURLEncoding.DecodeString(k.state)
			if err == nil && delta != 0 {
				b[int(pos)%len(b)] ^= delta
				if m, ok := parseState(fuzzSecretA, base64.RawURLEncoding.EncodeToString(b)); ok && m != k.want {
					t.Fatalf("variant %d: endret dekodet byte ga andre claims %+v", i, m)
				}
			}
		}
	})
}
