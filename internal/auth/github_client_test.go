package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/idp"
)

// ghTestServer samler det klienten sender, slik at testene kan sjekke
// headere og skjema, og lar hver test velge svar.
type ghTestServer struct {
	srv     *httptest.Server
	tokenH  func(w http.ResponseWriter, r *http.Request)
	userH   func(w http.ResponseWriter, r *http.Request)
	emailH  func(w http.ResponseWriter, r *http.Request)
	lastReq map[string]*http.Request
	form    url.Values
}

func newGHTestServer(t *testing.T) (*ghTestServer, *githubClient) {
	t.Helper()
	s := &ghTestServer{lastReq: map[string]*http.Request{}}
	mux := http.NewServeMux()
	handle := func(path string, h func() func(http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.lastReq[path] = r
			if path == "/login/oauth/access_token" {
				_ = r.ParseForm()
				s.form = r.PostForm
			}
			if f := h(); f != nil {
				f(w, r)
				return
			}
			http.NotFound(w, r)
		})
	}
	handle("/login/oauth/access_token", func() func(http.ResponseWriter, *http.Request) { return s.tokenH })
	handle("/user", func() func(http.ResponseWriter, *http.Request) { return s.userH })
	handle("/user/emails", func() func(http.ResponseWriter, *http.Request) { return s.emailH })
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s, &githubClient{http: idp.NewHTTPClient(true), baseURL: s.srv.URL, apiURL: s.srv.URL}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestGitHubExchange_RequestShapeAndSuccess(t *testing.T) {
	s, c := newGHTestServer(t)
	s.tokenH = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"access_token":"gho_tok","token_type":"bearer","scope":"read:user"}`)
	}
	tok, err := c.exchange(context.Background(), "cid", "sec", "the-code", "https://h.example/github-callback", "verif")
	require.NoError(t, err)
	require.Equal(t, "gho_tok", tok)

	r := s.lastReq["/login/oauth/access_token"]
	require.Equal(t, http.MethodPost, r.Method)
	require.Equal(t, "application/json", r.Header.Get("Accept"))
	require.Equal(t, "kauth", r.Header.Get("User-Agent"))
	require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
	require.Equal(t, url.Values{
		"client_id":     {"cid"},
		"client_secret": {"sec"},
		"code":          {"the-code"},
		"redirect_uri":  {"https://h.example/github-callback"},
		"code_verifier": {"verif"},
	}, s.form)
}

func TestGitHubExchange_Failures(t *testing.T) {
	const leak = "SECRET-DESCRIPTION-FROM-GITHUB"
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"status 500": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 500, `{"access_token":"x","token_type":"bearer"}`)
		},
		"status 401":   func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{}`) },
		"ugyldig json": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{not json`) },
		"tom kropp":    func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, ``) },
		"error med 200": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"error":"bad_verification_code","error_description":"`+leak+`"}`)
		},
		"error og token": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"error":"x","access_token":"t","token_type":"bearer"}`)
		},
		"tom access_token": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"access_token":"","token_type":"bearer"}`)
		},
		"uten access_token": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"token_type":"bearer"}`) },
		"token_type mac": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"access_token":"t","token_type":"mac"}`)
		},
		"uten token_type":   func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"access_token":"t"}`) },
		"redirect (avvist)": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
	} {
		t.Run(name, func(t *testing.T) {
			s, c := newGHTestServer(t)
			s.tokenH = h
			tok, err := c.exchange(context.Background(), "cid", "sec", "code", "https://h/cb", "v")
			require.ErrorIs(t, err, errGHCodeExchange)
			require.Empty(t, tok)
			require.NotContains(t, err.Error(), leak, "feiltekst fra GitHub skal ikke kunne nå brukeren")
			require.NotContains(t, err.Error(), "bad_verification_code")
		})
	}
}

func TestGitHubExchange_TokenTypeCaseInsensitive(t *testing.T) {
	for _, typ := range []string{"bearer", "Bearer", "BEARER"} {
		s, c := newGHTestServer(t)
		s.tokenH = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"access_token":"t","token_type":"`+typ+`"}`)
		}
		tok, err := c.exchange(context.Background(), "c", "s", "x", "https://h/cb", "v")
		require.NoError(t, err, typ)
		require.Equal(t, "t", tok)
	}
}

func TestGitHubExchange_TransportFailure(t *testing.T) {
	s, c := newGHTestServer(t)
	s.srv.Close()
	_, err := c.exchange(context.Background(), "c", "s", "x", "https://h/cb", "v")
	require.ErrorIs(t, err, errGHCodeExchange)
	require.NotContains(t, err.Error(), "127.0.0.1")
}

func TestGitHubExchange_ContextCancelled(t *testing.T) {
	s, c := newGHTestServer(t)
	s.tokenH = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"access_token":"t","token_type":"bearer"}`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.exchange(ctx, "c", "s", "x", "https://h/cb", "v")
	require.ErrorIs(t, err, errGHCodeExchange)
}

func TestGitHubUser_HeadersAndSuccess(t *testing.T) {
	s, c := newGHTestServer(t)
	s.userH = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":9007199254740993,"login":"octo","name":"Octo Cat","extra":{"a":1}}`)
	}
	u, err := c.user(context.Background(), "tok")
	require.NoError(t, err)
	sub, err := u.subject()
	require.NoError(t, err)
	require.Equal(t, "9007199254740993", sub, "id over 2^53 skal ikke rundes")
	require.Equal(t, "Octo Cat", u.Name)

	r := s.lastReq["/user"]
	require.Equal(t, http.MethodGet, r.Method)
	require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
	require.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
	require.Equal(t, "2022-11-28", r.Header.Get("X-GitHub-Api-Version"))
	require.Equal(t, "kauth", r.Header.Get("User-Agent"))
}

func TestGitHubUser_NullNameIsEmpty(t *testing.T) {
	s, c := newGHTestServer(t)
	s.userH = func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"id":5,"name":null}`) }
	u, err := c.user(context.Background(), "tok")
	require.NoError(t, err)
	require.Empty(t, u.Name)
}

func TestGitHubUser_IDValidation(t *testing.T) {
	for name, body := range map[string]string{
		"manglende":     `{"name":"x"}`,
		"null":          `{"id":null}`,
		"streng":        `{"id":"123"}`,
		"flyttall 1.0":  `{"id":1.0}`,
		"eksponent":     `{"id":1e3}`,
		"negativ":       `{"id":-5}`,
		"null-verdi 0":  `{"id":0}`,
		"for stor":      `{"id":9223372036854775808}`,
		"boolsk":        `{"id":true}`,
		"objekt":        `{"id":{}}`,
		"array":         `{"id":[1]}`,
		"ledende pluss": `{"id":+5}`,
	} {
		t.Run(name, func(t *testing.T) {
			s, c := newGHTestServer(t)
			s.userH = func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, body) }
			_, err := c.user(context.Background(), "tok")
			if name == "ledende pluss" {
				// Ugyldig JSON, så det er en hentefeil og ikke en manglende id.
				require.ErrorIs(t, err, errGHUserFetch)
				return
			}
			require.ErrorIs(t, err, errGHMissingID)
		})
	}
}

func TestGitHubUser_FetchFailures(t *testing.T) {
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"status 500":    func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, `{"id":5}`) },
		"status 401":    func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{"message":"Bad credentials"}`) },
		"ugyldig json":  func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{`) },
		"navn som tall": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"id":5,"name":7}`) },
		"redirect":      func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusFound) },
	} {
		t.Run(name, func(t *testing.T) {
			s, c := newGHTestServer(t)
			s.userH = h
			_, err := c.user(context.Background(), "tok")
			require.ErrorIs(t, err, errGHUserFetch)
			require.NotContains(t, err.Error(), "Bad credentials")
		})
	}
}

func TestGitHubEmails(t *testing.T) {
	s, c := newGHTestServer(t)
	s.emailH = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `[{"email":"a@example.com","primary":true,"verified":true,"visibility":"public"},{"email":"b@example.com","primary":false,"verified":false}]`)
	}
	got, err := c.emails(context.Background(), "tok")
	require.NoError(t, err)
	require.Equal(t, []ghEmail{{"a@example.com", true, true}, {"b@example.com", false, false}}, got)

	r := s.lastReq["/user/emails"]
	require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
	require.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
	require.Equal(t, "2022-11-28", r.Header.Get("X-GitHub-Api-Version"))
	require.Equal(t, "kauth", r.Header.Get("User-Agent"))
}

func TestGitHubEmails_Failures(t *testing.T) {
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"status 500":   func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, `[]`) },
		"status 403":   func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 403, `[]`) },
		"ugyldig json": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `[`) },
		"objekt":       func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `{"email":"a@b.c"}`) },
	} {
		t.Run(name, func(t *testing.T) {
			s, c := newGHTestServer(t)
			s.emailH = h
			_, err := c.emails(context.Background(), "tok")
			require.ErrorIs(t, err, errGHUserFetch)
		})
	}
}

func TestGitHubClient_OversizedResponseFailsLoudly(t *testing.T) {
	s, c := newGHTestServer(t)
	s.userH = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"id":5,"name":"`+strings.Repeat("a", 2<<20)+`"}`)
	}
	_, err := c.user(context.Background(), "tok")
	require.ErrorIs(t, err, errGHUserFetch)
}

func TestGitHubClient_NoSecretsInErrors(t *testing.T) {
	s, c := newGHTestServer(t)
	s.userH = func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, `{}`) }
	_, err := c.user(context.Background(), "gho_supersecret")
	require.NotContains(t, err.Error(), "gho_supersecret")
	b, _ := json.Marshal(err.Error())
	require.NotContains(t, string(b), "supersecret")
}

func TestPickEmail(t *testing.T) {
	e := func(addr string, primary, verified bool) ghEmail { return ghEmail{addr, primary, verified} }
	tests := []struct {
		name    string
		in      []ghEmail
		email   string
		trusted bool
	}{
		{"primær og verifisert", []ghEmail{e("kari@example.com", true, true)}, "kari@example.com", true},
		{"primær ikke først", []ghEmail{e("x@example.com", false, true), e("kari@example.com", true, true)}, "kari@example.com", true},
		{"uverifisert primær", []ghEmail{e("kari@example.com", true, false)}, "", false},
		{"verifisert ikke-primær", []ghEmail{e("kari@example.com", false, true)}, "", false},
		{"verifisert ikke-primær og uverifisert primær", []ghEmail{e("a@example.com", false, true), e("b@example.com", true, false)}, "", false},
		{"noreply", []ghEmail{e("1+kari@users.noreply.github.com", true, true)}, "", false},
		{"noreply store bokstaver", []ghEmail{e("1+kari@Users.NoReply.GitHub.com", true, true)}, "", false},
		{"noreply uten id", []ghEmail{e("kari@USERS.NOREPLY.GITHUB.COM", true, true)}, "", false},
		{"noreply-roten", []ghEmail{e("kari@noreply.github.com", true, true)}, "", false},
		{"annet underdomene av noreply", []ghEmail{e("kari@x.NoReply.github.com", true, true)}, "", false},
		{"underdomene av noreply er ikke noreply", []ghEmail{e("kari@a.users.noreply.github.com.example.com", true, true)}, "kari@a.users.noreply.github.com.example.com", true},
		{"ikke-ASCII", []ghEmail{e("kari@exämple.com", true, true)}, "", false},
		{"Kelvin-tegn", []ghEmail{e("Kari@example.com", true, true)}, "", false},
		{"mellomrom først", []ghEmail{e(" kari@example.com", true, true)}, "", false},
		{"mellomrom sist", []ghEmail{e("kari@example.com ", true, true)}, "", false},
		{"NBSP sist", []ghEmail{e("kari@example.com ", true, true)}, "", false},
		{"to primære", []ghEmail{e("a@example.com", true, true), e("b@example.com", true, true)}, "", false},
		{"to primære, bare én verifisert", []ghEmail{e("a@example.com", true, false), e("b@example.com", true, true)}, "", false},
		{"to @", []ghEmail{e("a@b@example.com", true, true)}, "", false},
		{"uten @", []ghEmail{e("kari", true, true)}, "", false},
		{"tom adresse", []ghEmail{e("", true, true)}, "", false},
		{"tom liste", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			email, trusted := pickEmail(tc.in)
			require.Equal(t, tc.email, email)
			require.Equal(t, tc.trusted, trusted)
		})
	}
}
