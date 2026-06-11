package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

type Provider interface {
	Name() string
	FetchServers(ctx context.Context, minServers int) (servers []models.Server, err error)
}

func (u *Updater) updateProvider(ctx context.Context, provider Provider,
	manifest manifest, minRatio float64,
) (err error) {
	providerName := provider.Name()
	existingServersCount := u.storage.GetServersCount(providerName)
	minServers := int(minRatio * float64(existingServersCount))

	var servers []models.Server
	if manifest.providerToFilepath == nil {
		servers, err = provider.FetchServers(ctx, minServers)
		switch {
		case errors.Is(err, common.ErrNotEnoughServers):
			u.logger.Warn("note: if running the update manually, you can use the flag " +
				"-minratio to allow the update to succeed with less servers found")
			fallthrough
		case err != nil:
			return fmt.Errorf("getting %s servers: %w", providerName, err)
		}
	} else {
		providerFilepath := manifest.providerToFilepath[providerName]
		providerFileURL := buildProviderFileURL(providerName, providerFilepath)

		var data models.Servers
		err = u.fetchJSON(ctx, providerFileURL, &data)
		if err != nil {
			return fmt.Errorf("downloading provider file %s: %w", providerFileURL, err)
		}
		servers = data.Servers
		if len(servers) < minServers {
			return fmt.Errorf("provider %s has not enough servers from downloaded file: got %d and expected at least %d",
				providerName, len(servers), minServers)
		}
	}

	for _, server := range servers {
		err := server.HasMinimumInformation()
		if err != nil {
			serverJSON, jsonErr := json.Marshal(server)
			if jsonErr != nil {
				panic(jsonErr)
			}
			return fmt.Errorf("server %s has not enough information: %w", serverJSON, err)
		}
	}

	if u.storage.ServersAreEqual(providerName, servers) {
		return nil
	}

	// Note the servers variable must NOT BE MUTATED after this call,
	// since the implementation does not deep copy the servers.
	// TODO set in storage in provider updater directly, server by server,
	// to avoid accumulating server data in memory.
	err = u.storage.SetServers(providerName, servers)
	if err != nil {
		return fmt.Errorf("setting servers to storage: %w", err)
	}
	return nil
}

func buildProviderFileURL(providerName, filePath string) (providerFileURL string) {
	filename := path.Base(filePath)
	if filename == "." || filename == "/" || filename == "" {
		filename = providerName + ".json"
	}

	const serversFilesBaseURL = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/"
	return serversFilesBaseURL + url.PathEscape(filename)
}
