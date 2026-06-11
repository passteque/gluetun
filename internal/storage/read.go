package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// readFromFile reads the servers data starting from the given manifest file path.
// It only reads servers that have the same version as the hardcoded servers version
// to avoid JSON decoding errors.
func (s *Storage) readFromFile(manifestPath string, hardcodedVersions map[string]uint16) (
	servers models.AllServers, found bool, err error,
) {
	file, err := os.Open(manifestPath)
	if os.IsNotExist(err) {
		return servers, false, nil
	} else if err != nil {
		return servers, false, err
	}

	b, err := io.ReadAll(file)
	if err != nil {
		return servers, true, err
	}

	if err := file.Close(); err != nil {
		return servers, true, err
	}

	if len(b) == 0 {
		// To satisfy https://github.com/qdm12/gluetun/issues/3318
		// not too sure why but eh I'm feeling generous adding 3 code lines for it.
		return servers, false, nil
	}

	servers, err = s.extractServersFromBytes(b, hardcodedVersions)
	return servers, true, err
}

func (s *Storage) extractServersFromBytes(b []byte, hardcodedVersions map[string]uint16) (
	servers models.AllServers, err error,
) {
	rawMessages := make(map[string]json.RawMessage)
	if err := json.Unmarshal(b, &rawMessages); err != nil {
		return servers, fmt.Errorf("decoding servers: %w", err)
	}

	// Note schema version is at map key "version" as number
	if rawVersion, ok := rawMessages["version"]; ok {
		err := json.Unmarshal(rawVersion, &servers.Version)
		if err != nil {
			return servers, fmt.Errorf("decoding servers schema version: %w", err)
		}
	}

	allProviders := providers.All()
	servers.ProviderToServers = make(map[string]models.Servers, len(allProviders))
	titleCaser := cases.Title(language.English)
	for _, provider := range allProviders {
		hardcodedVersion, ok := hardcodedVersions[provider]
		if !ok {
			panicOnProviderMissingHardcoded(provider)
		}

		rawMessage, ok := rawMessages[provider]
		if !ok {
			// If the provider is not found in the data bytes, just don't set it in
			// the providers map. That way the hardcoded servers will override them.
			// This is user provided and could come from different sources in the
			// future (e.g. a file or API request).
			continue
		}

		mergedServers, versionsMatch, err := s.readServers(provider,
			hardcodedVersion, rawMessage, titleCaser)
		if err != nil {
			return models.AllServers{}, err
		} else if !versionsMatch {
			// mergedServers is the empty struct in this case, so don't set the key
			// in the providerToServers map.
			continue
		}
		servers.ProviderToServers[provider] = mergedServers
	}

	return servers, nil
}

func (s *Storage) readServers(provider string, hardcodedVersion uint16,
	rawMessage json.RawMessage, titleCaser cases.Caser) (servers models.Servers,
	versionsMatch bool, err error,
) {
	provider = titleCaser.String(provider)

	var metadata struct {
		Version   uint16 `json:"version"`
		Timestamp uint64 `json:"timestamp"`
		Filepath  string `json:"filepath"`
	}

	err = json.Unmarshal(rawMessage, &metadata)
	if err != nil {
		return servers, false, fmt.Errorf("decoding servers version for provider %s: %w",
			provider, err)
	}

	if metadata.Filepath != "" {
		return s.readServersFromFilepath(provider, metadata.Filepath, hardcodedVersion)
	}

	err = json.Unmarshal(rawMessage, &servers)
	if err != nil {
		return servers, false, fmt.Errorf("decoding servers for provider %s: %w",
			provider, err)
	}

	const sourcePath = ""
	if !checkVersions(hardcodedVersion, servers.Version, provider, sourcePath,
		servers.Preferred, s.logger) {
		return models.Servers{}, false, nil
	}

	return servers, true, nil
}

func (s *Storage) readServersFromFilepath(provider, filepath string, hardcodedVersion uint16) (
	referencedServers models.Servers, versionsMatch bool, err error,
) {
	providerFile, err := os.Open(filepath)
	if os.IsNotExist(err) {
		return models.Servers{}, false, nil
	} else if err != nil {
		return models.Servers{}, false, fmt.Errorf("opening servers file %s for provider %s: %w",
			filepath, provider, err)
	}
	defer providerFile.Close()

	err = json.NewDecoder(providerFile).Decode(&referencedServers)
	if err != nil {
		return models.Servers{}, false, fmt.Errorf("decoding servers file %s for provider %s: %w",
			filepath, provider, err)
	}

	if !checkVersions(hardcodedVersion, referencedServers.Version, provider, filepath,
		referencedServers.Preferred, s.logger) {
		return models.Servers{}, false, nil
	}

	referencedServers.Filepath = filepath
	return referencedServers, true, nil
}

func checkVersions(builtinVersion, version uint16, provider, sourcePath string,
	preferred bool, logger Logger,
) (match bool) {
	if version == builtinVersion {
		return true
	}
	name := provider
	log := logger.Info
	if preferred {
		name += " preferred"
		log = logger.Warn
	}
	name += " servers"
	if sourcePath != "" {
		name += " from file " + sourcePath
	}
	log(fmt.Sprintf(
		"%s discarded because they have version %d and hardcoded servers have version %d",
		name, version, builtinVersion))
	return false
}
