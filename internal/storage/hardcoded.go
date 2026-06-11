package storage

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	serversmodule "github.com/qdm12/gluetun-servers/pkg/servers"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
)

func parseHardcodedServers() (allServers models.AllServers) {
	allProviders := providers.All()

	const version = 1
	allServers.ProviderToServers = make(map[string]models.Servers, len(allProviders))
	allServers.Version = version
	for _, provider := range allProviders {
		filename := provider + ".json"
		providerFile, err := serversmodule.Files.Open(filename)
		if err != nil {
			panic(fmt.Sprintf("reading embedded provider file %s for %s: %s", filename, provider, err))
		}
		defer providerFile.Close() // no-op

		var providerServers models.Servers
		decoder := json.NewDecoder(providerFile)
		err = decoder.Decode(&providerServers)
		if err != nil {
			panic(fmt.Sprintf("JSON decoding embedded provider file %s for %s: %s",
				filename, provider, err))
		} else if providerServers.Filepath != "" {
			panic(fmt.Sprintf("embedded provider file %s for %s should not have filepath set",
				filename, provider))
		}

		const serversPath = "/gluetun/servers/"
		providerServers.Filepath = filepath.Join(serversPath, filename)
		allServers.ProviderToServers[provider] = providerServers
	}

	return allServers
}
