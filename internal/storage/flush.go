package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/qdm12/gluetun/internal/models"
)

// flushToFile flushes the merged servers data to files
// using the manifest file path given. It is not thread-safe.
func (s *Storage) flushToFile(manifestPath string) error {
	const (
		filePermission = 0o644
		dirPermission  = 0o755
	)

	serversDirectoryPath := filepath.Dir(manifestPath)
	if err := os.MkdirAll(serversDirectoryPath, dirPermission); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	for provider, providerServers := range s.mergedServers.ProviderToServers {
		providerFilepath := providerServers.Filepath
		if providerFilepath == "" {
			providerFilepath = filepath.Join(serversDirectoryPath, provider+".json")
		}

		providerDirectoryPath := filepath.Dir(providerFilepath)
		if err := os.MkdirAll(providerDirectoryPath, dirPermission); err != nil {
			return fmt.Errorf("creating directory: %w", err)
		}
	}

	metadata := map[string]any{"version": s.mergedServers.Version}

	for provider, providerServers := range s.mergedServers.ProviderToServers {
		sort.Sort(models.SortableServers(providerServers.Servers))

		providerFilepath := providerServers.Filepath
		if providerFilepath == "" {
			providerFilepath = filepath.Join(serversDirectoryPath, provider+".json")
		}

		providerFile, err := os.OpenFile(providerFilepath,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePermission)
		if err != nil {
			return fmt.Errorf("opening servers data file for %s: %w", provider, err)
		}

		encodedProviderServers := providerServers
		encodedProviderServers.Filepath = ""

		encoder := json.NewEncoder(providerFile)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(encodedProviderServers)
		if err != nil {
			_ = providerFile.Close()
			return fmt.Errorf("encoding servers data for %s: %w", provider, err)
		}

		err = providerFile.Close()
		if err != nil {
			return fmt.Errorf("closing servers data file for %s: %w", provider, err)
		}

		metadata[provider] = map[string]string{"filepath": providerFilepath}
	}

	serversFile, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePermission)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(serversFile)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(metadata)
	if err != nil {
		_ = serversFile.Close()
		return err
	}

	return serversFile.Close()
}
