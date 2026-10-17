package auth

import (
	"path"
	"strings"
	"testing"
)

// FuzzMaskPath: for enhver sti med et magic-login- eller link-segment som
// følges av et segment, skal ingenting etter markøren i utdataene være annet
// enn ***. Sjekkes på segmentnivå, så et token som tilfeldigvis er en
// delstreng av "magic-login" ikke gir falske funn.
func FuzzMaskPath(f *testing.F) {
	f.Add("/magic-login/SECRETTOKEN")
	f.Add("//magic-login/X")
	f.Add("/Magic-Login/X")
	f.Add("/./magic-login/X/extra")
	f.Add("/a/../link/tok")
	f.Add("/link/link/tok")
	f.Add("/x/LINK/abc/def")
	f.Add("magic-login/%2Ftok")
	f.Add("/magic-login/" + strings.Repeat("A", 400))

	f.Fuzz(func(t *testing.T, p string) {
		segs := strings.Split(path.Clean("/"+p), "/")
		marker := -1
		for i, s := range segs {
			if (strings.EqualFold(s, "magic-login") || strings.EqualFold(s, "link")) && i < len(segs)-1 {
				marker = i
				break
			}
		}
		out := maskPath(p)
		if len(out) > maxLoggedPath {
			t.Fatalf("utdata lengre enn %d", maxLoggedPath)
		}
		if marker < 0 {
			return
		}
		os := strings.Split(out, "/")
		if len(os) <= marker+1 {
			return // avkortet før eller i markøren
		}
		if os[marker+1] != "***" && !strings.HasPrefix("***", os[marker+1]) {
			t.Fatalf("segment etter markør lekker: maskPath(%q) = %q", p, out)
		}
		if len(os) > marker+2 {
			t.Fatalf("segmenter etter ***: maskPath(%q) = %q", p, out)
		}
	})
}
