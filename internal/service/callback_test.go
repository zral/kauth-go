package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zral/kauth-go/internal/db/gen"
)

func TestNormalizeCallbackURLs(t *testing.T) {
	ok := []struct{ in, want string }{
		{"https://a.no/cb", "https://a.no/cb"},
		{" https://a.no/cb , https://b.no/cb?x=1 ", "https://a.no/cb,https://b.no/cb?x=1"},
		{"HTTPS://a.no/cb", "HTTPS://a.no/cb"},
		{"http://localhost:8080/cb", "http://localhost:8080/cb"},
		{"http://127.0.0.1/cb", "http://127.0.0.1/cb"},
		{"http://[::1]:3000/cb", "http://[::1]:3000/cb"},
	}
	for _, c := range ok {
		got, err := NormalizeCallbackURLs(c.in)
		assert.NoError(t, err, c.in)
		assert.Equal(t, c.want, got, c.in)
	}
	bad := []string{
		"", "   ", "https://a.no/cb,", ",https://a.no/cb", "https://a.no/cb,,https://b.no/cb",
		"/relativ", "a.no/cb", "http://a.no/cb", "http://localhost.evil.no/cb",
		"ftp://a.no/cb", "javascript:alert(1)", "https:///cb", "https://u:p@a.no/cb",
		"https://a.no/cb#frag", "https://a.no/cb#", "https://a.no/c b", "https://%zz", "https://",
	}
	for _, in := range bad {
		_, err := NormalizeCallbackURLs(in)
		if assert.Error(t, err, in) && in != "" {
			assert.NotContains(t, err.Error(), in)
		}
	}
}

func TestCallbackURLsAndPrimary(t *testing.T) {
	assert.Equal(t, []string{"https://a.no/cb", "https://b.no/cb"}, CallbackURLs(" https://a.no/cb, ,https://b.no/cb,"))
	assert.Empty(t, CallbackURLs(" , "))
	assert.Equal(t, "https://a.no/cb", PrimaryCallback(&gen.Service{CallbackUrl: " https://a.no/cb ,https://b.no/cb"}))
	assert.Equal(t, "", PrimaryCallback(&gen.Service{CallbackUrl: " , "}))
}

func TestNormalizeCallbackURLs_Boundaries(t *testing.T) {
	for _, bad := range []string{
		"HTTPS://", "https:///x", "http://localhost.evil.com", "http://127.0.0.1@evil.com",
		"https://a.no/cb, ,https://b.no", ",", "https://a.no/cb,", "https://a.no/cb#x", "https://a.no/cb#",
		"http://127.0.0.1.evil.com/cb", "https://:80/cb", "ftp://a.no", "//a.no/cb",
	} {
		_, err := NormalizeCallbackURLs(bad)
		assert.Error(t, err, bad)
	}
	for _, ok := range []string{"http://[::1]:8080/cb", "HTTPS://a.no/cb"} {
		_, err := NormalizeCallbackURLs(ok)
		assert.NoError(t, err, ok)
	}
}
