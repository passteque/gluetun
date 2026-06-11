package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDebURLs(t *testing.T) {
	t.Parallel()

	const html = `
		<html>
		  <body>
		    <a href="https://example.com/ignore.txt">ignore</a>
		    <a href="https://dhnx3d2u57yhc.cloudfront.net/cross-platform/linux-gui/2.8.9/PureVPN_amd64.deb">v2.8.9</a>
		    <a href="/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb">v2.9.0</a>
		    <a href='cross-platform/linux-gui/2.9.1/PureVPN_amd64.deb'>v2.9.1</a>
		  </body>
		</html>`

	debURLs, err := extractDebURLs(html, "https://www.purevpn.com/download/linux-vpn")
	require.NoError(t, err)

	assert.Contains(t, debURLs,
		"https://dhnx3d2u57yhc.cloudfront.net/cross-platform/linux-gui/2.8.9/PureVPN_amd64.deb")
	assert.Contains(t, debURLs,
		"https://www.purevpn.com/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb")
	assert.Contains(t, debURLs,
		"https://www.purevpn.com/download/cross-platform/linux-gui/2.9.1/PureVPN_amd64.deb")
}

func Test_chooseDebURL(t *testing.T) {
	t.Parallel()

	debURLs := []string{
		"https://cdn.example.com/cross-platform/linux-gui/2.9.0/PureVPN_arm64.deb",
		"https://cdn.example.com/cross-platform/linux-cli/2.9.1/PureVPN_amd64.deb",
		"https://cdn.example.com/cross-platform/linux-gui/2.8.9/PureVPN_amd64.deb",
		"https://cdn.example.com/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb",
	}

	bestURL, err := chooseDebURL(debURLs)
	require.NoError(t, err)

	assert.Equal(t,
		"https://cdn.example.com/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb",
		bestURL)
}
