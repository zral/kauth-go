package idp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGuard(t *testing.T) {
	blocked := []string{
		"127.0.0.1:443", "[::1]:443", "10.1.2.3:443", "172.16.0.1:443", "172.31.255.255:443",
		"192.168.1.1:443", "169.254.169.254:80", "100.64.0.1:443", "100.127.255.254:443",
		"[fc00::1]:443", "[fd12::1]:443", "[::ffff:10.0.0.1]:443", "[::ffff:127.0.0.1]:443",
		"0.0.0.0:443", "[::]:443", "0.1.2.3:443", "192.0.0.5:443", "198.18.0.1:443", "198.19.255.1:443",
		"224.0.0.1:443", "[ff02::1]:443", "[fe80::1]:443", "[64:ff9b::a00:1]:443",
		"[64:ff9b:1::1]:443", "[2002::1]:443", "[2001::1]:443", "[::2]:443", "[fec0::1]:443",
		"[2001:db8::1]:443", "240.0.0.1:443", "255.255.255.255:443", "[fe80::1%eth0]:443",
		"[::ffff:0.0.0.0]:443", "[::1]:443",
		"example.com:443", "garbage",
	}
	for _, a := range blocked {
		require.Error(t, guard("tcp", a, nil), a)
	}
	for _, a := range []string{"8.8.8.8:443", "93.184.216.34:443", "[2606:4700:4700::1111]:443", "100.128.0.1:443", "172.32.0.1:443"} {
		require.NoError(t, guard("tcp", a, nil), a)
	}
}

func TestGuardLoopbackOK(t *testing.T) {
	for _, a := range []string{"127.0.0.1:80", "[::1]:80", "[::ffff:127.0.0.1]:80"} {
		require.NoError(t, guardLoopbackOK("tcp", a, nil), a)
	}
	for _, a := range []string{"10.0.0.1:80", "169.254.169.254:80", "0.0.0.0:80", "192.168.0.1:80",
		"[64:ff9b:1::1]:80", "[2002::1]:80", "[2001::1]:80", "[::2]:80", "[fec0::1]:80", "[2001:db8::1]:80",
		"240.0.0.1:80", "255.255.255.255:80", "[fe80::1%eth0]:80", "[::ffff:0.0.0.0]:80"} {
		require.Error(t, guardLoopbackOK("tcp", a, nil), a)
	}
	require.NoError(t, guardLoopbackOK("tcp", "8.8.8.8:443", nil))
}

func TestClient_AvviserLoopbackUtenAllowInsecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := NewHTTPClient(false).Get(srv.URL)
	require.Error(t, err) // http avvises før dial
	_, err = NewHTTPClient(false).Get(strings.Replace(srv.URL, "http://", "https://", 1))
	require.Error(t, err) // dial-vakten avviser loopback
}

func TestClient_HttpAvvistUtenAllowInsecure(t *testing.T) {
	_, err := NewHTTPClient(false).Get("http://idp.example/.well-known/openid-configuration")
	require.ErrorContains(t, err, "bare https")
}

func TestClient_HttpBareLoopbackMedAllowInsecure(t *testing.T) {
	_, err := NewHTTPClient(true).Get("http://idp.example/x")
	require.ErrorContains(t, err, "bare https")
	_, err = NewHTTPClient(true).Get("http://10.0.0.1/x")
	require.ErrorContains(t, err, "bare https")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	resp, err := NewHTTPClient(true).Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
}

func TestClient_RedirectAvvises(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	_, err := NewHTTPClient(true).Get(srv.URL)
	require.Error(t, err)
	require.False(t, hit)
}

func TestClient_StorrelseGrense(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(strings.Repeat("a", maxBodyBytes)))
		case "/stor":
			w.Write([]byte(strings.Repeat("a", maxBodyBytes+1)))
		case "/chunked":
			f := w.(http.Flusher)
			for i := 0; i < 3; i++ {
				w.Write([]byte(strings.Repeat("a", maxBodyBytes/2)))
				f.Flush()
			}
		}
	}))
	defer srv.Close()
	c := NewHTTPClient(true)

	read := func(path string) (int, error) {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		n := 0
		buf := make([]byte, 32*1024)
		for {
			k, err := resp.Body.Read(buf)
			n += k
			if err != nil {
				if err.Error() == "EOF" {
					err = nil
				}
				return n, err
			}
		}
	}
	n, err := read("/ok")
	require.NoError(t, err)
	require.Equal(t, maxBodyBytes, n)
	_, err = read("/stor")
	require.Error(t, err)
	_, err = read("/chunked")
	require.Error(t, err)
}

func TestClient_IngenProxy(t *testing.T) {
	hits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	// Go lar uansett loopback gå utenom miljø-proxyen, så treff-tellingen alene
	// beviser lite; det er Proxy == nil under som låser valget.
	u, _ := url.Parse(srv.URL)
	c := NewHTTPClient(true)
	resp, err := c.Get("http://" + u.Host)
	require.NoError(t, err)
	resp.Body.Close()
	require.Zero(t, hits)
	tr := c.Transport.(*limitTransport).base.(*http.Transport)
	require.Nil(t, tr.Proxy)
}

func TestClient_ContentLengthOverGrense(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxBodyBytes+1))
		w.Write([]byte("kort"))
	}))
	defer srv.Close()
	_, err := NewHTTPClient(true).Get(srv.URL)
	require.Error(t, err)
}
