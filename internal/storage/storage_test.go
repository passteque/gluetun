package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Info(string)          {}
func (noopLogger) Infof(string, ...any) {}
func (noopLogger) Warn(string)          {}

// Test_New_custom_servers_directory checks that with a non-default
// STORAGE_SERVERS_DIRECTORY_PATH, all provider files and the manifest
// are written to the configured directory (and nowhere else).
func Test_New_custom_servers_directory(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		directoryName string
		trailingSlash bool
	}{
		"simple_directory":         {directoryName: "servers"},
		"nested_directory":         {directoryName: "nested/path/servers"},
		"directory_trailing_slash": {directoryName: "servers", trailingSlash: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			directoryPath := filepath.Join(t.TempDir(), testCase.directoryName)
			if testCase.trailingSlash {
				directoryPath += "/"
			}
			legacyFilepath := filepath.Join(t.TempDir(), "servers.json")

			storage, err := New(noopLogger{}, true, directoryPath, legacyFilepath)
			require.NoError(t, err)
			_ = storage

			// the directory must contain the manifest and one file
			// per provider, and nothing else.
			entries, err := os.ReadDir(directoryPath)
			require.NoError(t, err)
			require.Lenf(t, entries, len(providers.All())+1,
				"expecting the manifest and one file per provider")

			manifestFile, err := os.Open(filepath.Join(directoryPath, manifestFilename))
			require.NoError(t, err)
			defer manifestFile.Close()

			var manifest map[string]json.RawMessage
			err = json.NewDecoder(manifestFile).Decode(&manifest)
			require.NoError(t, err)
			require.Len(t, manifest, len(providers.All())+1) // +1 for "version"

			for _, provider := range providers.All() {
				var metadata struct {
					Filepath string `json:"filepath"`
				}
				err = json.Unmarshal(manifest[provider], &metadata)
				require.NoErrorf(t, err, "for provider %s", provider)

				expectedFilepath := filepath.Join(directoryPath, provider+".json")
				assert.Equalf(t, expectedFilepath, metadata.Filepath,
					"for provider %s", provider)

				providerFile, err := os.Open(metadata.Filepath)
				require.NoErrorf(t, err, "for provider %s", provider)
				assert.NoError(t, providerFile.Close())
			}
		})
	}
}
