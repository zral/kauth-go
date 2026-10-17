package githubtest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	cid      = "e19-gh-client-x"
	secret   = "s3cret-value"
	redirect = "https://auth.example.test/github-callback"
	verifier = "verifier-verifier-verifier-verifier-1234"
)

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var noRedirect = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func authorize(t *testing.T, s *Server, mut func(url.Values)) *http.Response {
	t.Helper()
	q := url.Values{"client_id": {cid}, "redirect_uri": {redirect}, "state": {"st"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	if mut != nil {
		mut(q)
	}
	resp, err := noRedirect.Get(s.URL() + "/login/oauth/authorize?" + q.Encode())
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func getCode(t *testing.T, s *Server) string {
	t.Helper()
	resp := authorize(t, s, nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "auth.example.test", loc.Host)
	require.Equal(t, "st", loc.Query().Get("state"))
	require.NotEmpty(t, loc.Query().Get("code"))
	return loc.Query().Get("code")
}

func exchange(t *testing.T, s *Server, code string, mut func(url.Values)) (int, map[string]any) {
	t.Helper()
	f := url.Values{"client_id": {cid}, "client_secret": {secret}, "code": {code},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}
	if mut != nil {
		mut(f)
	}
	req, _ := http.NewRequest(http.MethodPost, s.URL()+"/login/oauth/access_token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func apiGet(t *testing.T, s *Server, path, tok string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, s.URL()+path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func control(t *testing.T, s *Server, path, body string) int {
	t.Helper()
	resp, err := http.Post(s.URL()+path, "application/json", strings.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func newTestServer(t *testing.T) *Server {
	return New(t, Options{Secrets: []string{secret, "annen"}})
}

func fullFlow(t *testing.T, s *Server) string {
	t.Helper()
	status, out := exchange(t, s, getCode(t, s), nil)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "bearer", out["token_type"])
	require.Equal(t, "read:user,user:email", out["scope"])
	tok, _ := out["access_token"].(string)
	require.NotEmpty(t, tok)
	return tok
}

func TestHappyPath(t *testing.T) {
	s := newTestServer(t)
	tok := fullFlow(t, s)
	status, body := apiGet(t, s, "/user", tok)
	require.Equal(t, 200, status)
	require.JSONEq(t, `{"id":1001,"login":"testuser","name":"Test Bruker"}`, body)
	status, body = apiGet(t, s, "/user/emails", tok)
	require.Equal(t, 200, status)
	require.JSONEq(t, `[{"email":"gh-user@example.test","primary":true,"verified":true}]`, body)
}

func TestAuthorizeValidation(t *testing.T) {
	s := newTestServer(t)
	for name, mut := range map[string]func(url.Values){
		"client_id":   func(q url.Values) { q.Del("client_id") },
		"redirect":    func(q url.Values) { q.Del("redirect_uri") },
		"state":       func(q url.Values) { q.Del("state") },
		"challenge":   func(q url.Values) { q.Del("code_challenge") },
		"plain":       func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"relative":    func(q url.Values) { q.Set("redirect_uri", "/cb") },
		"no_method":   func(q url.Values) { q.Del("code_challenge_method") },
		"rel_no_host": func(q url.Values) { q.Set("redirect_uri", "https:///x") },
	} {
		require.Equal(t, http.StatusBadRequest, authorize(t, s, mut).StatusCode, name)
	}
}

func TestTokenRejections(t *testing.T) {
	s := newTestServer(t)
	cases := map[string]struct {
		mut  func(url.Values)
		want string
	}{
		"secret":   {func(f url.Values) { f.Set("client_secret", "feil") }, "incorrect_client_credentials"},
		"nosecret": {func(f url.Values) { f.Del("client_secret") }, "incorrect_client_credentials"},
		"client":   {func(f url.Values) { f.Set("client_id", "annen-klient") }, "incorrect_client_credentials"},
		"redirect": {func(f url.Values) { f.Set("redirect_uri", redirect+"x") }, "redirect_uri_mismatch"},
		"verifier": {func(f url.Values) { f.Set("code_verifier", "feil") }, "bad_verification_code"},
		"noverif":  {func(f url.Values) { f.Del("code_verifier") }, "bad_verification_code"},
		"badcode":  {func(f url.Values) { f.Set("code", "finnes-ikke") }, "bad_verification_code"},
	}
	for name, c := range cases {
		status, out := exchange(t, s, getCode(t, s), c.mut)
		require.Equal(t, http.StatusOK, status, name)
		require.Equal(t, c.want, out["error"], name)
		require.NotContains(t, out, "access_token", name)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := newTestServer(t)
	code := getCode(t, s)
	_, out := exchange(t, s, code, nil)
	require.NotEmpty(t, out["access_token"])
	_, out = exchange(t, s, code, nil)
	require.Equal(t, "bad_verification_code", out["error"])
}

func TestWrongSecretDoesNotBurnCode(t *testing.T) {
	s := newTestServer(t)
	code := getCode(t, s)
	_, out := exchange(t, s, code, func(f url.Values) { f.Set("client_secret", "feil") })
	require.Equal(t, "incorrect_client_credentials", out["error"])
	_, out = exchange(t, s, code, nil)
	require.NotEmpty(t, out["access_token"])
}

func TestFixedClients(t *testing.T) {
	s := New(t, Options{Clients: map[string]string{cid: secret}})
	require.Equal(t, http.StatusFound, authorize(t, s, nil).StatusCode)
	require.Equal(t, http.StatusBadRequest, authorize(t, s, func(q url.Values) { q.Set("client_id", "ukjent") }).StatusCode)
	_, out := exchange(t, s, getCode(t, s), func(f url.Values) { f.Set("client_secret", "feil") })
	require.Equal(t, "incorrect_client_credentials", out["error"])
}

func TestAPIRequiresIssuedToken(t *testing.T) {
	s := newTestServer(t)
	for _, p := range []string{"/user", "/user/emails"} {
		status, _ := apiGet(t, s, p, "")
		require.Equal(t, 401, status)
		status, _ = apiGet(t, s, p, "gho_ikke-utstedt")
		require.Equal(t, 401, status)
	}
}

func TestControlUser(t *testing.T) {
	s := newTestServer(t)
	require.Equal(t, 204, control(t, s, "/_control/user",
		`{"id":4711,"name":"Kari \"K\"","emails":[{"email":"a@b.test","primary":true,"verified":false},{"email":"c@d.test","primary":false,"verified":true}]}`))
	tok := fullFlow(t, s)
	_, body := apiGet(t, s, "/user", tok)
	require.JSONEq(t, `{"id":4711,"login":"testuser","name":"Kari \"K\""}`, body)
	_, body = apiGet(t, s, "/user/emails", tok)
	require.JSONEq(t, `[{"email":"a@b.test","primary":true,"verified":false},{"email":"c@d.test","primary":false,"verified":true}]`, body)

	// id sendes uendret: streng og 0 kan settes direkte.
	require.Equal(t, 204, control(t, s, "/_control/user", `{"id":"x","name":"N","emails":[]}`))
	_, body = apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":"x"`)
	_, body = apiGet(t, s, "/user/emails", tok)
	require.JSONEq(t, `[]`, body)
	require.Equal(t, 204, control(t, s, "/_control/user", `{"id":0,"name":"N"}`))
	_, body = apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":0,`)

	require.Equal(t, 400, control(t, s, "/_control/user", `{ikke json`))
}

func TestModes(t *testing.T) {
	s := newTestServer(t)
	setMode := func(m string) { require.Equal(t, 204, control(t, s, "/_control/mode", `{"mode":"`+m+`"}`)) }

	setMode("token_error_200")
	status, out := exchange(t, s, getCode(t, s), nil)
	require.Equal(t, 200, status)
	require.NotEmpty(t, out["error"])
	require.NotContains(t, out, "access_token")

	setMode("token_bad_type")
	_, out = exchange(t, s, getCode(t, s), nil)
	require.Equal(t, "mac", out["token_type"])

	setMode("token_500")
	status, _ = exchange(t, s, getCode(t, s), nil)
	require.Equal(t, 500, status)

	setMode("normal")
	tok := fullFlow(t, s)

	setMode("user_500")
	status, _ = apiGet(t, s, "/user", tok)
	require.Equal(t, 500, status)
	status, _ = apiGet(t, s, "/user/emails", tok)
	require.Equal(t, 200, status)

	setMode("emails_500")
	status, _ = apiGet(t, s, "/user/emails", tok)
	require.Equal(t, 500, status)
	status, _ = apiGet(t, s, "/user", tok)
	require.Equal(t, 200, status)

	setMode("id_string")
	_, body := apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":"1001"`)
	setMode("id_zero")
	_, body = apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":0,`)

	setMode("normal")
	_, body = apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":1001,`)

	require.Equal(t, 400, control(t, s, "/_control/mode", `{"mode":"finnes_ikke"}`))
	require.Equal(t, 400, control(t, s, "/_control/mode", `{}`))
}

func TestSlowModeDelaysTokenEndpoint(t *testing.T) {
	s := New(t, Options{Secrets: []string{secret}, SlowDelay: 300 * time.Millisecond})
	code := getCode(t, s)
	s.SetMode(ModeSlow)
	start := time.Now()
	_, out := exchange(t, s, code, nil)
	require.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)
	require.NotEmpty(t, out["access_token"])
}

func TestCallsLogHasBooleansOnly(t *testing.T) {
	s := newTestServer(t)
	code := getCode(t, s)
	exchange(t, s, code, func(f url.Values) { f.Set("code_verifier", "feil") })
	code = getCode(t, s)
	_, out := exchange(t, s, code, nil)
	tok := out["access_token"].(string)
	apiGet(t, s, "/user", tok)
	apiGet(t, s, "/user/emails", "")

	resp, err := http.Get(s.URL() + "/_control/calls")
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, secretish := range []string{secret, verifier, tok, code, "gh-user@example.test"} {
		require.NotContains(t, string(raw), secretish)
	}
	var calls []map[string]any
	require.NoError(t, json.Unmarshal(raw, &calls))
	paths := []string{}
	for _, c := range calls {
		paths = append(paths, c["path"].(string))
	}
	require.Equal(t, []string{"/login/oauth/authorize", "/login/oauth/access_token", "/login/oauth/authorize",
		"/login/oauth/access_token", "/user", "/user/emails"}, paths)
	require.Equal(t, false, calls[1]["verifier_ok"])
	require.Equal(t, true, calls[1]["client_secret_ok"])
	require.Equal(t, true, calls[1]["redirect_uri_ok"])
	require.Equal(t, true, calls[3]["verifier_ok"])
	require.Equal(t, true, calls[4]["auth_header_ok"])
	require.Equal(t, false, calls[5]["auth_header_ok"])

	// normal nullstiller loggen; reset nullstiller også brukeren.
	s.SetMode(ModeNormal)
	require.Empty(t, s.Calls())
}

func TestResetRestoresDefaults(t *testing.T) {
	s := newTestServer(t)
	s.SetUser(User{ID: json.RawMessage("7"), Name: "X"})
	s.SetMode(ModeUser500)
	require.Equal(t, 204, control(t, s, "/_control/reset", ``))
	tok := fullFlow(t, s)
	_, body := apiGet(t, s, "/user", tok)
	require.Contains(t, body, `"id":1001,`)
}

func TestRejectsNonLoopback(t *testing.T) {
	_, err := NewServer(Options{Addr: "0.0.0.0:0"})
	require.Error(t, err)
	_, err = NewServer(Options{Addr: "192.0.2.1:0"})
	require.Error(t, err)
}

// AK5.2: githubtest skal ikke havne i produksjonsbinæren, og bare importeres
// fra _test.go og cmd/kauth-testidp.
func TestNotImportedByProduction(t *testing.T) {
	prodDepsAndImporters(t)
}

func TestControlGuard(t *testing.T) {
	s := newTestServer(t)
	resp, err := http.Post(s.URL()+"/_control/mode", "text/plain", strings.NewReader(`{"mode":"slow"}`))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)

	req, err := http.NewRequest(http.MethodPost, s.URL()+"/_control/mode", strings.NewReader(`{"mode":"slow"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "evil.example:8097"
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	// Modusen er fortsatt normal: tokenendepunktet svarer uten forsinkelse.
	require.Empty(t, s.Calls())
}

// Feil JSON-typer i e-postlisten sendes uendret, så kauths parsing kan testes.
func TestControlUserRawEmails(t *testing.T) {
	s := newTestServer(t)
	require.Equal(t, 204, control(t, s, "/_control/user", `{"id":1,"name":"N","emails":[{"email":"a@b.test","primary":true,"verified":"true"}]}`))
	s.mu.Lock()
	raw := string(s.user.EmailsRaw)
	s.mu.Unlock()
	require.JSONEq(t, `[{"email":"a@b.test","primary":true,"verified":"true"}]`, raw)
}
