package storage

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func populateProviderToVersion(providerToVersion map[string]uint16) map[string]uint16 {
	allProviders := providers.All()
	for _, provider := range allProviders {
		_, has := providerToVersion[provider]
		if has {
			continue
		}

		providerToVersion[provider] = 0
	}
	return providerToVersion
}

func Test_extractServersFromBytes(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		b                 []byte
		hardcodedVersions map[string]uint16
		makeLogger        func(ctrl *gomock.Controller) *MockLogger
		persisted         models.AllServers
		errMessage        string
	}{
		"bad JSON": {
			b:          []byte("garbage"),
			makeLogger: func(_ *gomock.Controller) *MockLogger { return nil },
			errMessage: "decoding servers: invalid character 'g' looking for beginning of value",
		},
		"bad provider JSON": {
			b:                 []byte(`{"cyberghost": "garbage"}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{}),
			makeLogger:        func(_ *gomock.Controller) *MockLogger { return nil },
			errMessage: "decoding servers version for provider Cyberghost: " +
				"json: cannot unmarshal string into Go value of type struct { Version uint16 \"json:\\\"version\\\"\"; " +
				"Timestamp uint64 \"json:\\\"timestamp\\\"\"; " +
				"Filepath string \"json:\\\"filepath\\\"\" }",
		},
		"bad servers array JSON": {
			b: []byte(`{"cyberghost": {"version": 1, "servers": "garbage"}}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{
				providers.Cyberghost: 1,
			}),
			makeLogger: func(_ *gomock.Controller) *MockLogger { return nil },
			errMessage: "decoding servers for provider Cyberghost: " +
				"json: cannot unmarshal string into Go struct field Servers.servers of type []models.Server",
		},
		"absent provider keys": {
			b: []byte(`{}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{
				providers.Cyberghost: 1,
			}),
			makeLogger: func(_ *gomock.Controller) *MockLogger { return nil },
			persisted: models.AllServers{
				ProviderToServers: map[string]models.Servers{},
			},
		},
		"same versions": {
			b: []byte(`{
					"cyberghost": {"version": 1, "timestamp": 0}
				}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{
				providers.Cyberghost: 1,
			}),
			makeLogger: func(_ *gomock.Controller) *MockLogger { return nil },
			persisted: models.AllServers{
				ProviderToServers: map[string]models.Servers{
					providers.Cyberghost: {Version: 1},
				},
			},
		},
		"different versions": {
			b: []byte(`{
				"cyberghost": {"version": 1, "timestamp": 1}
			}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{
				providers.Cyberghost: 2,
			}),
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Info("Cyberghost servers discarded because " +
					"they have version 1 and hardcoded servers have version 2")
				return logger
			},
			persisted: models.AllServers{
				ProviderToServers: map[string]models.Servers{},
			},
		},
		"preferred_different_versions": {
			b: []byte(`{
				"cyberghost": {"version": 1, "timestamp": 1, "preferred": true}
			}`),
			hardcodedVersions: populateProviderToVersion(map[string]uint16{
				providers.Cyberghost: 2,
			}),
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warn("Cyberghost preferred servers discarded because " +
					"they have version 1 and hardcoded servers have version 2")
				return logger
			},
			persisted: models.AllServers{
				ProviderToServers: map[string]models.Servers{},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			logger := testCase.makeLogger(ctrl)
			s := &Storage{
				logger: logger,
			}

			servers, err := s.extractServersFromBytes(testCase.b, testCase.hardcodedVersions)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.persisted, servers)
		})
	}

	t.Run("hardcoded panic", func(t *testing.T) {
		t.Parallel()

		s := &Storage{}

		allProviders := providers.All()
		require.GreaterOrEqual(t, len(allProviders), 2)

		b := []byte(`{}`)
		hardcodedVersions := map[string]uint16{
			allProviders[0]: 1,
			// Missing provider allProviders[1]
		}
		expectedPanicValue := fmt.Sprintf("provider %s not found in hardcoded servers map", allProviders[1])
		assert.PanicsWithValue(t, expectedPanicValue, func() {
			_, _ = s.extractServersFromBytes(b, hardcodedVersions)
		})
	})
}
