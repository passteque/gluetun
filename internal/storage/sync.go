package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/qdm12/gluetun/internal/models"
)

func countServers(allServers models.AllServers) (count int) {
	for _, servers := range allServers.ProviderToServers {
		count += len(servers.Servers)
	}
	return count
}

// syncServers merges the hardcoded servers with the ones from on disk files.
// It assumes s.directoryPath is set.
func (s *Storage) syncServers() (err error) {
	hardcodedVersions := make(map[string]uint16, len(s.hardcodedServers.ProviderToServers))
	for provider, servers := range s.hardcodedServers.ProviderToServers {
		hardcodedVersions[provider] = servers.Version
	}

	sourceManifestPath := filepath.Join(s.directoryPath, manifestFilename)
	destinationManifestPath := sourceManifestPath
	serversOnFile, found, err := s.readFromFile(sourceManifestPath, hardcodedVersions)
	if err != nil {
		return fmt.Errorf("reading servers from file: %w", err)
	}

	hasLegacy := s.hasLegacy()
	if !found && hasLegacy {
		sourceManifestPath = s.legacyFilepath
		s.logger.Infof("reading legacy servers file %s and migrating it to directory %s", sourceManifestPath, s.directoryPath)
		serversOnFile, _, err = s.readFromFile(sourceManifestPath, hardcodedVersions)
		if err != nil {
			return fmt.Errorf("reading servers from file: %w", err)
		}
	}

	hardcodedCount := countServers(s.hardcodedServers)
	countOnFile := countServers(serversOnFile)

	s.mergedMutex.Lock()
	defer s.mergedMutex.Unlock()

	if countOnFile == 0 {
		s.logger.Info(fmt.Sprintf(
			"writing servers data files to %s with %d hardcoded servers",
			s.directoryPath, hardcodedCount))
		s.mergedServers = s.hardcodedServers
	} else {
		s.logger.Info(fmt.Sprintf(
			"merging by most recent %d hardcoded servers and %d servers read from manifest file %s",
			hardcodedCount, countOnFile, sourceManifestPath))

		s.mergedServers = s.mergeServers(s.hardcodedServers, serversOnFile)
	}

	// Eventually write file
	if reflect.DeepEqual(serversOnFile, s.mergedServers) {
		return nil
	}

	err = s.flushToFile(destinationManifestPath)
	if err != nil {
		s.logger.Warn("failed writing servers to destination manifest: " + err.Error())
		return nil
	}

	migratedFromLegacy := hasLegacy && sourceManifestPath == s.legacyFilepath
	if migratedFromLegacy {
		err = os.Remove(sourceManifestPath)
		if err != nil && !os.IsNotExist(err) {
			s.logger.Warn("failed removing legacy servers file " + sourceManifestPath + ": " + err.Error())
		}
	}
	return nil
}
