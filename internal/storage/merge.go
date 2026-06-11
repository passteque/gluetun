package storage

import (
	"fmt"
	"sort"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/format"
	"github.com/qdm12/gluetun/internal/models"
)

func (s *Storage) mergeServers(hardcoded, persisted models.AllServers) models.AllServers {
	allProviders := providers.All()
	merged := models.AllServers{
		Version:           hardcoded.Version,
		ProviderToServers: make(map[string]models.Servers, len(allProviders)),
	}

	for _, provider := range allProviders {
		hardcodedServers := hardcoded.ProviderToServers[provider]
		persistedServers := persisted.ProviderToServers[provider]
		merged.ProviderToServers[provider] = s.mergeProviderServers(provider,
			hardcodedServers, persistedServers)
	}

	return merged
}

func (s *Storage) mergeProviderServers(provider string,
	hardcoded, persisted models.Servers,
) (merged models.Servers) {
	if persisted.Preferred && persisted.Version != hardcoded.Version {
		s.logger.Warn(fmt.Sprintf(
			"persisted preferred %s servers are discarded because they have version %d and hardcoded servers have version %d",
			provider, persisted.Version, hardcoded.Version))
	}

	// If persisted data is marked as preferred, use it regardless of timestamp
	// (as long as versions match)
	if persisted.Preferred && persisted.Version == hardcoded.Version && len(persisted.Servers) > 0 {
		s.logger.Info(fmt.Sprintf(
			"Using %s servers from file (marked as preferred)", provider))
		return persisted
	}

	nowTimestamp := time.Now().Unix()
	if persisted.Timestamp > nowTimestamp {
		s.logger.Warn(fmt.Sprintf(
			"persisted %s servers have a timestamp %d in the future, ignoring them",
			provider, persisted.Timestamp))
	} else if persisted.Timestamp > hardcoded.Timestamp {
		diff := time.Unix(persisted.Timestamp, 0).Sub(time.Unix(hardcoded.Timestamp, 0))
		if diff < 0 {
			diff = -diff
		}
		diff = diff.Truncate(time.Second)
		message := "Using " + provider + " servers from file which are " +
			format.FriendlyDuration(diff) + " more recent"
		s.logger.Info(message)

		return persisted
	}

	persistedServerKeyToServer := make(map[string]models.Server)
	for _, persistedServer := range persisted.Servers {
		if persistedServer.Keep {
			persistedServerKeyToServer[persistedServer.Key()] = persistedServer
		}
	}

	merged = hardcoded // use all fields from hardcoded
	merged.Servers = make([]models.Server, 0, len(hardcoded.Servers)+len(persistedServerKeyToServer))

	for _, hardcodedServer := range hardcoded.Servers {
		hardcodedServerKey := hardcodedServer.Key()
		persistedServerToKeep, has := persistedServerKeyToServer[hardcodedServerKey]
		if has {
			// Drop hardcoded server and use persisted server matching the key.
			merged.Servers = append(merged.Servers, persistedServerToKeep)
			delete(persistedServerKeyToServer, hardcodedServerKey)
		} else {
			merged.Servers = append(merged.Servers, hardcodedServer)
		}
	}

	// Add remaining persisted servers to keep
	for _, persistedServer := range persistedServerKeyToServer {
		merged.Servers = append(merged.Servers, persistedServer)
	}

	sort.Sort(models.SortableServers(merged.Servers))

	return merged
}
