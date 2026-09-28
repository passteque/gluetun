package updater

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDebURL(t *testing.T) {
	t.Parallel()

	html, err := os.ReadFile("testdata/index.html")
	require.NoError(t, err)

	debURLs, err := extractDebURL(string(html), "https://www.purevpn.com/download/linux-vpn")
	require.NoError(t, err)

	const want = "https://dhnx3d2u57yhc.cloudfront.net/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb"

	assert.Equal(t, want, debURLs)
}
