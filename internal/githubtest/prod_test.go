package githubtest

import (
	"os/exec"
	"strings"
	"testing"
)

func prodDepsAndImporters(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go ikke i PATH")
	}
	run := func(args ...string) string {
		cmd := exec.Command("go", args...)
		cmd.Dir = "../.."
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go %v: %v", args, err)
		}
		return string(out)
	}
	if deps := run("list", "-deps", "./cmd/kauth"); strings.Contains(deps, "internal/githubtest") {
		t.Fatal("cmd/kauth avhenger av githubtest")
	}
	// {{.Imports}} teller ikke _test.go, så bare ikke-testkode vises her.
	for _, line := range strings.Split(run("list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./..."), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasSuffix(f[0], "/internal/githubtest") || strings.HasSuffix(f[0], "/cmd/kauth-testidp") {
			continue
		}
		for _, imp := range f[1:] {
			if strings.HasSuffix(imp, "/internal/githubtest") {
				t.Errorf("%s importerer githubtest utenfor _test.go", f[0])
			}
		}
	}
}
