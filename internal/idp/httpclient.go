package idp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

const maxBodyBytes = 1 << 20

var errBodyTooLarge = errors.New("idp: svarkroppen er over 1 MiB")

// Adresseblokker som ikke dekkes av netip sine Is*-metoder, men som aldri
// er en offentlig leverandør.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

func blockedAddr(ip netip.Addr, allowLoopback bool) bool {
	// IPv4-mappede adresser (::ffff:10.0.0.1) skal vurderes som IPv4.
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || !ip.IsValid() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// guard kjører etter DNS-oppslag, rett før connect, så et vertsnavn som
// løses til en intern adresse (SSRF, DNS-rebinding) stoppes uansett hva
// issuer-URL-en så ut som.
func guard(network, address string, c syscall.RawConn) error {
	return checkDial(false, address)
}

// guardLoopbackOK er guard for eval/utvikling: bare loopback slippes gjennom.
func guardLoopbackOK(network, address string, c syscall.RawConn) error {
	return checkDial(true, address)
}

func checkDial(allowLoopback bool, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("idp: ugyldig adresse: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("idp: dial uten IP-adresse avvist: %w", err)
	}
	if blockedAddr(ip, allowLoopback) {
		return errors.New("idp: adressen er ikke tillatt som utgående mål")
	}
	return nil
}

// NewHTTPClient lager klienten for all trafikk mot leverandører (discovery,
// JWKS, token-endepunkt). Egen transport, ingen proxy og ingen redirects.
func NewHTTPClient(allowInsecure bool) *http.Client {
	ctl := guard
	if allowInsecure {
		ctl = guardLoopbackOK
	}
	d := &net.Dialer{Timeout: 5 * time.Second, Control: ctl}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &limitTransport{base: tr, allowInsecure: allowInsecure},
		// En leverandør skal ikke kunne flytte oss til en annen vert.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("idp: redirect avvist")
		},
	}
}

type limitTransport struct {
	base          http.RoundTripper
	allowInsecure bool
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.schemeOK(req) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errors.New("idp: bare https er tillatt")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > maxBodyBytes {
		resp.Body.Close()
		return nil, errBodyTooLarge
	}
	resp.Body = &limitedBody{rc: resp.Body, left: maxBodyBytes}
	return resp, nil
}

func (t *limitTransport) schemeOK(req *http.Request) bool {
	if req.URL.Scheme == "https" {
		return true
	}
	if req.URL.Scheme != "http" || !t.allowInsecure {
		return false
	}
	h := strings.ToLower(req.URL.Hostname())
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// limitedBody feiler høyt ved overskridelse. En stille avkorting ville latt
// en avkortet JWKS eller discovery-JSON se gyldig ut.
type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n - 1, errBodyTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }
