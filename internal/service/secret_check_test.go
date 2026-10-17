package service

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zral/kauth-go/internal/db/gen"
)

func TestCheckClientSecrets_LogsNamesNeverValues(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	const plain, envVal = "KLARTEKST-HEMMELIGHET-XYZ", "ENV-HEMMELIGHET-XYZ"
	env := map[string]string{"KAUTH_SVC_OK_G": envVal, "KAUTH_PRIVATE_KEY_PEM": envVal, "KAUTH_SVC_GH_OK": envVal}
	r := testRegistry([]gen.Service{
		{ID: "ok", GoogleClientSecretEnv: strPtr("KAUTH_SVC_OK_G")},
		{ID: "tom", GoogleClientSecretEnv: strPtr("KAUTH_SVC_TOM_G"), MicrosoftClientSecretEnv: strPtr("KAUTH_SVC_TOM_M")},
		{ID: "ugyldig", GoogleClientSecretEnv: strPtr("KAUTH_PRIVATE_KEY_PEM")},
		{ID: "klar", MicrosoftClientSecret: strPtr(plain)},
		{ID: "ren"},
		{ID: "ghtom", GithubClientSecretEnv: strPtr("KAUTH_SVC_GH_TOM")},
		{ID: "ghok", GithubClientSecretEnv: strPtr("KAUTH_SVC_GH_OK")},
		{ID: "ghbad", GithubClientSecretEnv: strPtr("KAUTH_PRIVATE_KEY_PEM")},
	})
	r.CheckClientSecrets(func(k string) string { return env[k] })

	out := buf.String()
	for _, want := range []string{
		`service=tom method=google env=KAUTH_SVC_TOM_G`,
		`service=tom method=microsoft env=KAUTH_SVC_TOM_M`,
		`service=ugyldig method=google env=KAUTH_PRIVATE_KEY_PEM`,
		`klienthemmelighet i klartekst i DB`,
		`service=klar method=microsoft`,
		`service=ghtom method=github env=KAUTH_SVC_GH_TOM`,
		`service=ghbad method=github env=KAUTH_PRIVATE_KEY_PEM`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mangler %q i:\n%s", want, out)
		}
	}
	for _, bad := range []string{plain, envVal, "service=ok", "service=ren", "service=ghok"} {
		if strings.Contains(out, bad) {
			t.Errorf("uventet %q i logg:\n%s", bad, out)
		}
	}
}

func TestCheckClientSecrets_GitHubGlobalFallback(t *testing.T) {
	const idVal, secVal = "GLOBAL-ID-XYZ", "GLOBAL-SECRET-XYZ"
	run := func(env map[string]string, svcs ...gen.Service) string {
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		defer slog.SetDefault(old)
		testRegistry(svcs).CheckClientSecrets(func(k string) string { return env[k] })
		return buf.String()
	}
	on := func(id string, mut func(*gen.Service)) gen.Service {
		s := gen.Service{ID: id, AuthGithub: 1}
		if mut != nil {
			mut(&s)
		}
		return s
	}
	t.Run("ingenting satt gir begge varsler", func(t *testing.T) {
		out := run(nil, on("a", nil))
		for _, want := range []string{`service=a method=github env=KAUTH_GITHUB_CLIENT_SECRET`, `service=a method=github env=KAUTH_GITHUB_CLIENT_ID`} {
			if !strings.Contains(out, want) {
				t.Errorf("mangler %q i:\n%s", want, out)
			}
		}
	})
	t.Run("global verdi og egen referanse gir ingen varsler", func(t *testing.T) {
		env := map[string]string{"KAUTH_GITHUB_CLIENT_ID": idVal, "KAUTH_GITHUB_CLIENT_SECRET": secVal, "KAUTH_SVC_C": secVal}
		out := run(env, on("b", nil), on("c", func(s *gen.Service) {
			s.GithubClientID = strPtr("egen")
			s.GithubClientSecretEnv = strPtr("KAUTH_SVC_C")
		}))
		env2 := map[string]string{"KAUTH_SVC_C": secVal}
		out2 := run(env2, on("c", func(s *gen.Service) {
			s.GithubClientID = strPtr("egen")
			s.GithubClientSecretEnv = strPtr("KAUTH_SVC_C")
		}))
		if out != "" || out2 != "" {
			t.Errorf("uventet logg:\n%s\n%s", out, out2)
		}
	})
	t.Run("kun hemmelighet mangler, og kun for tjenester med metoden på", func(t *testing.T) {
		out := run(map[string]string{"KAUTH_GITHUB_CLIENT_ID": idVal},
			on("d", nil), gen.Service{ID: "av"})
		if !strings.Contains(out, "service=d method=github env=KAUTH_GITHUB_CLIENT_SECRET") || strings.Contains(out, "CLIENT_ID") || strings.Contains(out, "service=av") {
			t.Errorf("feil logg:\n%s", out)
		}
	})
	t.Run("verdier logges aldri", func(t *testing.T) {
		out := run(map[string]string{"KAUTH_GITHUB_CLIENT_ID": idVal}, on("e", nil))
		if strings.Contains(out, idVal) || strings.Contains(out, secVal) {
			t.Errorf("verdi i logg:\n%s", out)
		}
	})
}
