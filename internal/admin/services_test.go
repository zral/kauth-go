package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// 126 F2 (BACKLOG F19): auth_host valideres nå ved lagring — se validateAuthHost i services.go.

func TestValidateAuthHost_Empty(t *testing.T) {
	assert.NoError(t, validateAuthHost(""))
	assert.NoError(t, validateAuthHost("   "))
}

func TestValidateAuthHost_Valid(t *testing.T) {
	assert.NoError(t, validateAuthHost("auth.spekto.live"))
	assert.NoError(t, validateAuthHost("auth.klarsyn.net"))
	assert.NoError(t, validateAuthHost("localhost.local"))
}

func TestValidateAuthHost_RejectsScheme(t *testing.T) {
	err := validateAuthHost("https://auth.spekto.live")
	assert.Error(t, err)
}

func TestValidateAuthHost_RejectsPath(t *testing.T) {
	err := validateAuthHost("auth.spekto.live/login")
	assert.Error(t, err)
}

func TestValidateAuthHost_RejectsWhitespace(t *testing.T) {
	err := validateAuthHost("auth.spekto.live extra")
	assert.Error(t, err)
}

func TestValidateAuthHost_RejectsSingleLabel(t *testing.T) {
	// Ingen punktum — for tillatende ville akseptert åpenbare skrivefeil som "auth" alene.
	err := validateAuthHost("auth")
	assert.Error(t, err)
}

func TestValidateAuthHost_RejectsTrailingDot(t *testing.T) {
	err := validateAuthHost("auth.spekto.live.")
	assert.Error(t, err)
}
