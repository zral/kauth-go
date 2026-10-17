// kauth-testidp er en kjørbar testleverandør for eval-serveren (015 PD9).
// Den er et tynt skall rundt internal/oidctest og skal aldri nås utenfra:
// den utsteder tokens uten ekte autentisering, og oidctest krever loopback.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zral/kauth-go/internal/githubtest"
	"github.com/zral/kauth-go/internal/oidctest"
)

var modes = map[oidctest.Mode]bool{
	oidctest.ModeOK: true, oidctest.ModeWrongIss: true, oidctest.ModeWrongAud: true,
	oidctest.ModeMultiAudBadAzp: true, oidctest.ModeWrongNonce: true, oidctest.ModeExpired: true,
	oidctest.ModeUnknownKid: true, oidctest.ModeAlgNone: true, oidctest.ModeAlgHS256: true,
	oidctest.ModeRotateKey: true, oidctest.ModeNoIDToken: true, oidctest.ModeAuthorizeError: true,
	oidctest.ModeIssParamWrong: true, oidctest.ModeBadAzp: true, oidctest.ModeToken500: true,
	oidctest.ModeTokenSlow: true,
}

var discModes = map[oidctest.DiscoveryMode]bool{
	oidctest.DiscOK: true, oidctest.DiscWrongIss: true, oidctest.DiscHTTPEndpoint: true,
	oidctest.DiscRedirect: true, oidctest.DiscForeignJWKSHost: true, oidctest.DiscHuge: true,
	oidctest.DiscSlow: true, oidctest.DiscDown500: true,
}

type nextReq struct {
	oidctest.Claims
	Mode string `json:"mode"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8092", "lytteadresse (må være loopback)")
	issuer := flag.String("issuer", "", "issuer (default http://<addr>)")
	clientID := flag.String("client-id", "test-client", "klient-ID")
	clientSecret := flag.String("client-secret", "", "klienthemmelighet (tom = offentlig klient)")
	disc := flag.String("discovery-mode", "ok", "ok|wrong_issuer|http_endpoint|redirect|foreign_jwks_host|huge|slow|down500")
	gh := flag.Bool("github", false, "start fake-GitHub (019) i stedet for OIDC-leverandøren")
	ghSecrets := flag.String("github-secrets", "", "kommaseparerte klienthemmeligheter fake-GitHub godtar (bare med -github)")
	flag.Parse()

	if *gh {
		runGitHub(*addr, *ghSecrets)
		return
	}

	if !discModes[oidctest.DiscoveryMode(*disc)] {
		log.Fatalf("ukjent -discovery-mode %q", *disc)
	}
	if *issuer == "" {
		*issuer = "http://" + *addr
	}
	p, err := oidctest.NewServer(oidctest.Options{
		Addr:          *addr,
		Issuer:        *issuer,
		ClientID:      *clientID,
		ClientSecret:  *clientSecret,
		DiscoveryMode: oidctest.DiscoveryMode(*disc),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()

	p.Handle("POST /_control/next", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
		var req nextReq
		var keys map[string]json.RawMessage
		if err != nil || json.Unmarshal(body, &req) != nil || json.Unmarshal(body, &keys) != nil {
			http.Error(w, "ugyldig JSON", http.StatusBadRequest)
			return
		}
		// Manglende nøkkel betyr manglende claim; Claims-nullverdien er true.
		if _, ok := keys["email_verified"]; !ok {
			req.EmailVerified = oidctest.EVOmit
		}
		m := oidctest.Mode(req.Mode)
		if m == "" {
			m = oidctest.ModeOK
		}
		if !modes[m] {
			http.Error(w, "ukjent mode", http.StatusBadRequest)
			return
		}
		p.Next(req.Claims, m)
		w.WriteHeader(http.StatusNoContent)
	}))
	p.Handle("POST /_control/reset", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.Reset()
		w.WriteHeader(http.StatusNoContent)
	}))
	p.Handle("GET /_control/requests", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqs := p.Requests()
		if reqs == nil {
			reqs = []oidctest.Request{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reqs)
	}))

	fmt.Printf("kauth-testidp: issuer=%s client-id=%s discovery-mode=%s lytter=%s\n", *issuer, *clientID, *disc, p.URL())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

// runGitHub kjører fake-GitHub til SIGINT/SIGTERM. Hemmelighetene kommer fra
// flagget og skrives aldri ut.
func runGitHub(addr, secrets string) {
	var list []string
	for _, v := range strings.Split(secrets, ",") {
		if v = strings.TrimSpace(v); v != "" {
			list = append(list, v)
		}
	}
	if len(list) == 0 {
		log.Fatal("-github krever minst én hemmelighet i -github-secrets")
	}
	g, err := githubtest.NewServer(githubtest.Options{Addr: addr, Secrets: list})
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	fmt.Printf("kauth-testidp: github lytter=%s hemmeligheter=%d\n", g.URL(), len(list))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
