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
