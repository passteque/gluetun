package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_flushToFile_filepathOnlyInManifest(t *testing.T) {
	t.Parallel()

	tempPath := t.TempDir()
	providerFilepath := filepath.Join(tempPath, "provider.json")
	manifestPath := filepath.Join(tempPath, "manifest.json")

	storage := &Storage{
		mergedServers: models.AllServers{
			Version: 1,
			ProviderToServers: map[string]models.Servers{
				"provider": {
					Version:   1,
					Timestamp: 1,
					Filepath:  providerFilepath,
				},
			},
		},
	}

	err := storage.flushToFile(manifestPath)
	require.NoError(t, err)

	providerFile, err := os.Open(providerFilepath)
	require.NoError(t, err)
	defer providerFile.Close()

	providerContent := make(map[string]json.RawMessage)
	err = json.NewDecoder(providerFile).Decode(&providerContent)
	require.NoError(t, err)
	_, hasFilepath := providerContent["filepath"]
	assert.False(t, hasFilepath)

	manifestFile, err := os.Open(manifestPath)
	require.NoError(t, err)
	defer manifestFile.Close()

	manifestContent := make(map[string]json.RawMessage)
	err = json.NewDecoder(manifestFile).Decode(&manifestContent)
	require.NoError(t, err)

	providerMetadataRaw, ok := manifestContent["provider"]
	require.True(t, ok)

	var providerMetadata struct {
		Filepath string `json:"filepath"`
	}
	err = json.Unmarshal(providerMetadataRaw, &providerMetadata)
	require.NoError(t, err)
	assert.Equal(t, providerFilepath, providerMetadata.Filepath)
}
