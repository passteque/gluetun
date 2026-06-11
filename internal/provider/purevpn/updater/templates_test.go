package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseAtomAPIBaseURL(t *testing.T) {
	t.Parallel()

	content := []byte(`(0, _defineProperty2["default"])(AtomApi, "BASE_URL", "https://atomapi.com/");`)
	baseURL, err := parseAtomAPIBaseURL(content)
	require.NoError(t, err)
	assert.Equal(t, "https://atomapi.com/", baseURL)
}

func Test_parsePureVPNCountrySlug(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "us", parsePureVPNCountrySlug("usca2-auto-udp.ptoserver.com"))
	assert.Equal(t, "uk", parsePureVPNCountrySlug("uk2-auto-udp.ptoserver.com"))
	assert.Equal(t, "", parsePureVPNCountrySlug("broken-hostname"))
}

func Test_resolveAtomSecret(t *testing.T) {
	t.Parallel()

	extracted := resolveAtomSecret([]byte(`ATOM_SECRET:"fromasar123456"`))
	assert.Equal(t, "fromasar123456", extracted)
	fallback := resolveAtomSecret(nil)
	assert.Equal(t, defaultAtomSecret, fallback)
}
