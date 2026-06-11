package storage

import (
	"encoding/json"
	"path"
	"testing"

	"github.com/qdm12/gluetun-servers/pkg/servers"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseHardcodedServers(t *testing.T) {
	t.Parallel()

	var servers models.AllServers
	assert.NotPanics(t, func() {
		servers = parseHardcodedServers()
	})

	// all providers minus custom
	allProviders := providers.All()
	require.Equal(t, len(allProviders), len(servers.ProviderToServers))
	for _, provider := range allProviders {
		servers, ok := servers.ProviderToServers[provider]
		assert.Truef(t, ok, "for provider %s", provider)
		assert.NotEmptyf(t, servers, "for provider %s", provider)
	}
}

func Test_parseHardcodedServers_filepathsAndEmbeddedProviderFiles(t *testing.T) {
	t.Parallel()

	hardcodedServers := parseHardcodedServers()

	allProviders := providers.All()
	for _, provider := range allProviders {
		providerServers, ok := hardcodedServers.ProviderToServers[provider]
		require.Truef(t, ok, "for provider %s", provider)

		require.NotEmptyf(t, providerServers.Filepath,
			"embedded servers filepath should be set for provider %s", provider)

		filename := path.Base(providerServers.Filepath)
		file, err := servers.Files.Open(filename)
		require.NoErrorf(t, err, "opening embedded provider file for %s", provider)

		var fileServers struct {
			Version   uint16            `json:"version"`
			Timestamp int64             `json:"timestamp"`
			Servers   []json.RawMessage `json:"servers"`
		}
		err = json.NewDecoder(file).Decode(&fileServers)
		require.NoErrorf(t, err, "decoding embedded provider file for %s", provider)
		require.NoError(t, file.Close())

		assert.NotZerof(t, fileServers.Version, "for provider %s", provider)
		assert.NotZerof(t, fileServers.Timestamp, "for provider %s", provider)
		assert.NotEmptyf(t, fileServers.Servers, "for provider %s", provider)
	}
}
