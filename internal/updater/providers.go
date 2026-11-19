package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

type Provider interface {
	Name() string
	FetchServers(ctx context.Context, minServers int) (servers []models.Server, err error)
}

var ErrServerHasNotEnoughInformation = errors.New("server has not enough information")

func (u *Updater) updateProvider(ctx context.Context, provider Provider,
	minRatio float64,
) (err error) {
	providerName := provider.Name()
	existingServersCount := u.storage.GetServersCount(providerName)
	minServers := int(minRatio * float64(existingServersCount))
	servers, err := provider.FetchServers(ctx, minServers)
	if err != nil {
		if errors.Is(err, common.ErrNotEnoughServers) {
			u.logger.Warn("note: if running the update manually, you can use the flag " +
				"-minratio to allow the update to succeed with less servers found")
		}
		return fmt.Errorf("getting %s servers: %w", providerName, err)
	}

	// An empty list of servers would replace the stored ones with nothing.
	// This can happen when the minimum servers count is 0, because of the
	// -minratio flag or because a single server is stored.
	if len(servers) == 0 {
		return fmt.Errorf("no server found for provider %s", providerName)
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
