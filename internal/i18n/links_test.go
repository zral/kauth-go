package i18n

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinks_PreservesQueryAndSetsLang(t *testing.T) {
	u, err := url.Parse("/login?service=spekto&redirect_uri=https%3A%2F%2Fspekto.live%2Fcb&lang=nb")
	require.NoError(t, err)

	links := Links("nb", u)
	require.Len(t, links, 3)

	byCode := map[string]Link{}
	for _, l := range links {
		byCode[l.Code] = l
	}

	de, ok := byCode["de"]
	require.True(t, ok)
	assert.False(t, de.Active)
	assert.Equal(t, "DE", de.Label)
	assert.Equal(t, "Deutsch", de.Name)

	parsed, err := url.Parse(de.Href)
	require.NoError(t, err)
	assert.Equal(t, "/login", parsed.Path)
	assert.Empty(t, parsed.Host, "href skal være path-relativ så host ikke havner i markup")
	assert.Equal(t, "de", parsed.Query().Get("lang"), "lang skal overskrives, ikke dupliseres")
	assert.Equal(t, "spekto", parsed.Query().Get("service"))
	assert.Equal(t, "https://spekto.live/cb", parsed.Query().Get("redirect_uri"))

	assert.True(t, byCode["nb"].Active, "aktivt språk skal markeres")
	assert.False(t, byCode["en"].Active)
}

func TestLinks_NoExistingQuery(t *testing.T) {
	u, err := url.Parse("/magic-login")
	require.NoError(t, err)

	links := Links("en", u)
	require.Len(t, links, 3)
	// supported-rekkefølgen er nb, en, de.
	assert.Equal(t, "nb", links[0].Code)
	assert.Equal(t, "/magic-login?lang=nb", links[0].Href)
	assert.True(t, links[1].Active)
}

func TestLinks_AllHaveLabelAndName(t *testing.T) {
	u, err := url.Parse("/login")
	require.NoError(t, err)

	for _, l := range Links("en", u) {
		assert.NotEmpty(t, l.Label, "locale %s mangler Label", l.Code)
		assert.NotEmpty(t, l.Name, "locale %s mangler Name", l.Code)
		assert.NotEmpty(t, l.Href, "locale %s mangler Href", l.Code)
	}
}
