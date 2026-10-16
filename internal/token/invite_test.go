package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLinkInviteToken(t *testing.T) {
	a, ah, err := NewLinkInviteToken()
	require.NoError(t, err)
	b, _, err := NewLinkInviteToken()
	require.NoError(t, err)
	assert.Len(t, a, 43)
	assert.NotEqual(t, a, b)
	assert.Equal(t, HashOpaque(a), ah)
	assert.NotContains(t, a, "=")
}

func TestFormatLinkInviteTime_UTCFixedWidth(t *testing.T) {
	loc := time.FixedZone("x", 2*3600)
	assert.Equal(t, "2026-10-01T08:05:09Z", FormatLinkInviteTime(time.Date(2026, 10, 1, 10, 5, 9, 123, loc)))
}
