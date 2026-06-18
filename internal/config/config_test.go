package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseISO8601(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"PT15M", "15m0s"},
		{"PT8H", "8h0m0s"},
		{"P30D", "720h0m0s"},
		{"PT1H30M", "1h30m0s"},
	}
	for _, c := range cases {
		d, err := parseISO8601(c.input)
		require.NoError(t, err, c.input)
		assert.Equal(t, c.expected, d.String(), c.input)
	}
}

func TestParseISO8601_Invalid(t *testing.T) {
	_, err := parseISO8601("invalid")
	assert.Error(t, err)
}
