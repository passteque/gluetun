package storage

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"

	serversmodule "github.com/qdm12/gluetun-servers/pkg/servers"
	"github.com/qdm12/gluetun/internal/models"
)

//go:embed servers.json
var allServersEmbedFS embed.FS

func parseHardcodedServers() (allServers models.AllServers) {
	f, err := allServersEmbedFS.Open("servers.json")
	if err != nil {
		panic(err)
	}
	defer f.Close() // no-op
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&allServers)
	if err != nil {
		panic("decoding servers.json: " + err.Error())
	}

	for provider, metadata := range allServers.ProviderToServers {
		if metadata.Filepath == "" {
			panic(fmt.Sprintf("embedded manifest file servers.json should have the filepath field set for %s", provider))
		}
		filename := path.Base(metadata.Filepath)
		providerFile, err := serversmodule.Files.Open(filename)
		if err != nil {
			const rootURL = "https://github.com/qdm12/gluetun-servers/blob/main/pkg/servers"
			panic(fmt.Sprintf("reading embedded provider file defined at %s/%s.json: %s", rootURL, filename, err))
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

		providerServers.Filepath = metadata.Filepath // inherit filepath from servers.json
		allServers.ProviderToServers[provider] = providerServers
	}

	return allServers
}
