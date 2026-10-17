// Package githubtest er en fake GitHub for tester og eval (019 PD11). Den
// etterligner OAuth-endepunktene (authorize og access_token) og to REST-kall
// (/user og /user/emails), og lar testen styre brukeren og hvordan neste kall
// feiler.
//
// Pakken skal bare importeres fra _test.go og cmd/kauth-testidp, aldri fra
// produksjonskode: den godkjenner enhver innlogging uten ekte autentisering.
// Serveren lagrer og logger aldri hemmelighetsverdier, koder eller tokens;
// kall-loggen har bare boolske utfall per sjekk.
package githubtest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mode velger hva serveren gjør galt (PD11). ModeNormal nullstiller.
type Mode string

const (
	ModeNormal        Mode = "normal"
	ModeTokenError200 Mode = "token_error_200"
	ModeTokenBadType  Mode = "token_bad_type"
	ModeToken500      Mode = "token_500"
	ModeUser500       Mode = "user_500"
	ModeEmails500     Mode = "emails_500"
	ModeIDString      Mode = "id_string"
	ModeIDZero        Mode = "id_zero"
	ModeSlow          Mode = "slow"
)

// Modes er de gyldige modusene, for validering i kontrollendepunktet.
var Modes = map[Mode]bool{
	ModeNormal: true, ModeTokenError200: true, ModeTokenBadType: true, ModeToken500: true,
	ModeUser500: true, ModeEmails500: true, ModeIDString: true, ModeIDZero: true, ModeSlow: true,
}

// Email er én oppføring i /user/emails.
type Email struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// User er brukeren serveren svarer med. ID er rå JSON og sendes uendret i
// /user, slik at både tall, strenger og 0 kan testes.
type User struct {
	ID     json.RawMessage `json:"id"`
	Name   string          `json:"name"`
	Emails []Email         `json:"emails"`
}

// Call er én logget forespørsel. Bare sti og boolske utfall, aldri verdiene.
// Felt som ikke gjelder stien, utelates.
type Call struct {
	Path          string `json:"path"`
	Status        int    `json:"status"`
	ClientIDOK    *bool  `json:"client_id_ok,omitempty"`
	ClientSecret  *bool  `json:"client_secret_ok,omitempty"`
	VerifierOK    *bool  `json:"verifier_ok,omitempty"`
	RedirectURIOK *bool  `json:"redirect_uri_ok,omitempty"`
	CodeOK        *bool  `json:"code_ok,omitempty"`
	StateOK       *bool  `json:"state_ok,omitempty"`
	ChallengeOK   *bool  `json:"challenge_ok,omitempty"`
	AuthHeaderOK  *bool  `json:"auth_header_ok,omitempty"`
}

// Options setter opp serveren.
type Options struct {
	// Addr må være loopback. Tom gir 127.0.0.1:0.
	Addr string
	// Secrets er hemmeligheter som godtas for enhver client_id som ikke står i
	// Clients. Eval bruker dette, siden client id-ene seedes av scenarioene.
	Secrets []string
	// Clients er faste client_id til hemmelighet. Er den ikke tom, avvises
	// ukjente client_id.
	Clients map[string]string
	// SlowDelay er ventetiden i ModeSlow. Default 12 s, over kauths 10 s klienttidsavbrudd.
	SlowDelay time.Duration
}

type authCode struct {
	clientID, redirectURI, challenge string
	used                             bool
}

// Server er fake-GitHub.
type Server struct {
	opts Options
	srv  *httptest.Server
	mux  *http.ServeMux
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	mode   Mode
	user   User
	codes  map[string]*authCode
	tokens map[string]bool
	calls  []Call
}

// DefaultUser er brukeren før testen setter en annen.
func DefaultUser() User {
	return User{ID: json.RawMessage("1001"), Name: "Test Bruker",
		Emails: []Email{{Email: "gh-user@example.test", Primary: true, Verified: true}}}
}

// New starter serveren og stopper den ved testslutt.
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	s, err := NewServer(opts)
	if err != nil {
		t.Fatalf("githubtest: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// NewServer er varianten uten testing.TB, for cmd/kauth-testidp. Kall Close.
func NewServer(opts Options) (*Server, error) {
	if opts.SlowDelay == 0 {
		opts.SlowDelay = 12 * time.Second
	}
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if !loopbackAddr(addr) {
		return nil, fmt.Errorf("addr %q er ikke loopback", addr)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{opts: opts, done: make(chan struct{}), mode: ModeNormal, user: DefaultUser(),
		codes: map[string]*authCode{}, tokens: map[string]bool{}}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /login/oauth/authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /login/oauth/access_token", s.handleToken)
	s.mux.HandleFunc("GET /user", s.handleUser)
	s.mux.HandleFunc("GET /user/emails", s.handleEmails)
	s.mux.HandleFunc("POST /_control/user", controlGuard(s.handleControlUser))
	s.mux.HandleFunc("POST /_control/mode", controlGuard(s.handleControlMode))
	s.mux.HandleFunc("POST /_control/reset", controlGuard(s.handleControlReset))
	s.mux.HandleFunc("GET /_control/calls", controlGuard(s.handleControlCalls))
	s.srv = httptest.NewUnstartedServer(s.mux)
	s.srv.Listener.Close()
	s.srv.Listener = l
	s.srv.Start()
	return s, nil
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close stopper serveren og avbryter ventende forsinkelser.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		s.srv.Close()
	})
}

// URL er basis-URL-en, både for OAuth-endepunktene og API-et.
func (s *Server) URL() string { return s.srv.URL }

// SetUser setter brukeren som /user og /user/emails svarer med.
func (s *Server) SetUser(u User) {
	if len(u.ID) == 0 {
		u.ID = json.RawMessage("null")
	}
	s.mu.Lock()
	s.user = u
	s.mu.Unlock()
}

// SetMode setter modusen. ModeNormal nullstiller modus og kall-logg, men ikke brukeren.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	s.mode = m
	if m == ModeNormal {
		s.calls = nil
	}
	s.mu.Unlock()
}

// Reset nullstiller alt: modus, bruker, kall, koder og tokens.
func (s *Server) Reset() {
	s.mu.Lock()
	s.mode, s.user, s.calls = ModeNormal, DefaultUser(), nil
	s.codes, s.tokens = map[string]*authCode{}, map[string]bool{}
	s.mu.Unlock()
}

// Calls gir en kopi av kall-loggen.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

func (s *Server) record(c Call) {
	s.mu.Lock()
	s.calls = append(s.calls, c)
	s.mu.Unlock()
}

func (s *Server) currentMode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func bp(b bool) *bool { return &b }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// clientKnown sier om client_id godtas.
func (s *Server) clientKnown(id string) bool {
	if id == "" {
		return false
	}
	if len(s.opts.Clients) == 0 {
		return true
	}
	_, ok := s.opts.Clients[id]
	return ok
}

func (s *Server) secretOK(id, secret string) bool {
	if secret == "" {
		return false
	}
	if want, ok := s.opts.Clients[id]; ok {
		return eq(secret, want)
	}
	ok := false
	for _, w := range s.opts.Secrets {
		// Ingen tidlig retur: samme tid uansett hvilken som treffer.
		if eq(secret, w) {
			ok = true
		}
	}
	return ok
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, perr := url.Parse(q.Get("redirect_uri"))
	call := Call{Path: "/login/oauth/authorize",
		ClientIDOK:    bp(s.clientKnown(q.Get("client_id"))),
		RedirectURIOK: bp(perr == nil && redirect.IsAbs() && redirect.Host != ""),
		StateOK:       bp(q.Get("state") != ""),
		ChallengeOK:   bp(q.Get("code_challenge") != "" && q.Get("code_challenge_method") == "S256"),
	}
	if !*call.ClientIDOK || !*call.RedirectURIOK || !*call.StateOK || !*call.ChallengeOK {
		call.Status = http.StatusBadRequest
		s.record(call)
		http.Error(w, "ugyldig authorize-forespørsel", http.StatusBadRequest)
		return
	}
	code := randHex(16)
	s.mu.Lock()
	s.codes[code] = &authCode{clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge")}
	s.mu.Unlock()
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	call.Status = http.StatusFound
	s.record(call)
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// tokenError svarer slik GitHub gjør: status 200 med error i JSON-kroppen.
func tokenError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	call := Call{Path: "/login/oauth/access_token", Status: http.StatusOK}
	defer func() { s.record(call) }()
	mode := s.currentMode()
	switch mode {
	case ModeToken500:
		call.Status = http.StatusInternalServerError
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	case ModeSlow:
		select {
		case <-time.After(s.opts.SlowDelay):
		case <-s.done:
		case <-r.Context().Done():
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	form, perr := url.ParseQuery(string(body))
	if err != nil || perr != nil {
		tokenError(w, "bad_request", "ugyldig skjema")
		return
	}
	clientID := form.Get("client_id")
	call.ClientIDOK = bp(s.clientKnown(clientID))
	call.ClientSecret = bp(*call.ClientIDOK && s.secretOK(clientID, form.Get("client_secret")))
	if !*call.ClientSecret {
		tokenError(w, "incorrect_client_credentials", "The client_id and/or client_secret passed are incorrect.")
		return
	}
	s.mu.Lock()
	ac := s.codes[form.Get("code")]
	var snapshot authCode
	if ac != nil {
		snapshot = *ac
		// Engangskode: brent ved første forsøk med riktige klientlegitimasjoner,
		// også når PKCE eller redirect_uri feiler (som hos ekte leverandører).
		ac.used = true
	}
	s.mu.Unlock()
	call.CodeOK = bp(ac != nil && !snapshot.used)
	if !*call.CodeOK {
		tokenError(w, "bad_verification_code", "The code passed is incorrect or expired.")
		return
	}
	call.ClientIDOK = bp(eq(clientID, snapshot.clientID))
	call.RedirectURIOK = bp(eq(form.Get("redirect_uri"), snapshot.redirectURI))
	sum := sha256.Sum256([]byte(form.Get("code_verifier")))
	call.VerifierOK = bp(form.Get("code_verifier") != "" && eq(base64.RawURLEncoding.EncodeToString(sum[:]), snapshot.challenge))
	switch {
	case !*call.ClientIDOK:
		tokenError(w, "incorrect_client_credentials", "The client_id differs from the authorization request.")
		return
	case !*call.RedirectURIOK:
		tokenError(w, "redirect_uri_mismatch", "The redirect_uri does not match the authorization request.")
		return
	case !*call.VerifierOK:
		tokenError(w, "bad_verification_code", "PKCE verification failed.")
		return
	}
	if mode == ModeTokenError200 {
		tokenError(w, "bad_verification_code", "Forced error.")
		return
	}
	tok := "gho_" + randHex(20)
	s.mu.Lock()
	s.tokens[tok] = true
	s.mu.Unlock()
	typ := "bearer"
	if mode == ModeTokenBadType {
		typ = "mac"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": typ, "scope": "read:user,user:email"})
}

// authed sjekker Authorization: Bearer mot utstedte tokens.
func (s *Server) authed(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[tok]
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	call := Call{Path: "/user", Status: http.StatusOK, AuthHeaderOK: bp(s.authed(r))}
	defer func() { s.record(call) }()
	if !*call.AuthHeaderOK {
		call.Status = http.StatusUnauthorized
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	mode := s.currentMode()
	if mode == ModeUser500 {
		call.Status = http.StatusInternalServerError
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	u := s.user
	s.mu.Unlock()
	id := u.ID
	switch mode {
	case ModeIDString:
		id, _ = json.Marshal(strings.Trim(string(id), `"`))
	case ModeIDZero:
		id = json.RawMessage("0")
	}
	name, _ := json.Marshal(u.Name)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%s,"login":"testuser","name":%s}`, id, name)
}

func (s *Server) handleEmails(w http.ResponseWriter, r *http.Request) {
	call := Call{Path: "/user/emails", Status: http.StatusOK, AuthHeaderOK: bp(s.authed(r))}
	defer func() { s.record(call) }()
	if !*call.AuthHeaderOK {
		call.Status = http.StatusUnauthorized
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	if s.currentMode() == ModeEmails500 {
		call.Status = http.StatusInternalServerError
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	list := s.user.Emails
	s.mu.Unlock()
	if list == nil {
		list = []Email{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

// controlGuard stenger kontrollendepunktene for nettlesere på samme maskin:
// JSON-kravet tvinger frem CORS-preflight for kryss-opphav-POST, og Host-sjekken
// stopper DNS-rebinding. Lilleklo er også prod-boks, så eval-brukeren skal ikke
// kunne byttes av en tilfeldig nettside mens eval kjører.
func controlGuard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "bare loopback", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "krever application/json", http.StatusUnsupportedMediaType)
			return
		}
		h(w, r)
	}
}

func (s *Server) handleControlUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	var u User
	if err != nil || json.Unmarshal(body, &u) != nil {
		http.Error(w, "ugyldig JSON", http.StatusBadRequest)
		return
	}
	// id må være gyldig JSON (RawMessage sikrer det) og kan være tall eller streng.
	s.SetUser(u)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleControlMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<10))
	if err != nil || json.Unmarshal(body, &req) != nil || !Modes[Mode(req.Mode)] {
		http.Error(w, "ukjent mode", http.StatusBadRequest)
		return
	}
	s.SetMode(Mode(req.Mode))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleControlReset(w http.ResponseWriter, _ *http.Request) {
	s.Reset()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleControlCalls(w http.ResponseWriter, _ *http.Request) {
	calls := s.Calls()
	if calls == nil {
		calls = []Call{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(calls)
}
