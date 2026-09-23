package storage

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_mergeProviderServers(t *testing.T) {
	t.Parallel()

	const provider = providers.Protonvpn

	hardcodedServers := []models.Server{
		{VPN: "openvpn", Country: "USA", City: "New York", Hostname: "hardcoded.protonvpn.net", TCP: true, UDP: true},
	}
	persistedServers := []models.Server{
		{VPN: "openvpn", Country: "USA", City: "Chicago", Hostname: "persisted.protonvpn.net", TCP: true, UDP: true},
	}

	testCases := map[string]struct {
		hardcoded models.Servers
		persisted models.Servers
		logInfo   string
		logWarn   string
		expected  models.Servers
	}{
		"preferred_mismatching_version": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
			persisted: models.Servers{
				Version:   3,
				Timestamp: 50,
				Preferred: true,
				Servers:   persistedServers,
			},
			logWarn: "persisted preferred protonvpn servers are discarded because " +
				"they have version 3 and hardcoded servers have version 4",
			expected: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
		},
		"preferred_matching_version": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
			persisted: models.Servers{
				Version:   4,
				Timestamp: 50,
				Preferred: true,
				Servers:   persistedServers,
			},
			logInfo: "Using protonvpn servers from file (marked as preferred)",
			expected: models.Servers{
				Version:   4,
				Timestamp: 50,
				Preferred: true,
				Servers:   persistedServers,
			},
		},
		"preferred_empty_servers": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
			persisted: models.Servers{
				Version:   4,
				Timestamp: 50,
				Preferred: true,
			},
			expected: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
		},
		"not_preferred_newer_timestamp": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
			persisted: models.Servers{
				Version:   4,
				Timestamp: 150,
				Servers:   persistedServers,
			},
			logInfo: "Using protonvpn servers from file which are 50 seconds more recent",
			expected: models.Servers{
				Version:   4,
				Timestamp: 150,
				Servers:   persistedServers,
			},
		},
		"not_preferred_older_timestamp": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
			persisted: models.Servers{
				Version:   4,
				Timestamp: 50,
				Servers:   persistedServers,
			},
			expected: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers:   hardcodedServers,
			},
		},
		"not_preferred_kept_servers": {
			hardcoded: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers: []models.Server{
					{VPN: "openvpn", Country: "USA", City: "New York", Hostname: "a.protonvpn.net", TCP: true, UDP: true},
					{VPN: "openvpn", Country: "Canada", City: "Montreal", Hostname: "b.protonvpn.net", TCP: true, UDP: true},
				},
			},
			persisted: models.Servers{
				Version:   4,
				Timestamp: 50,
				Servers: []models.Server{
					{VPN: "openvpn", Country: "USA", City: "Chicago", Hostname: "a.protonvpn.net", TCP: true, UDP: true, Keep: true},
					{
						VPN: "openvpn", Country: "Germany", City: "Berlin", Hostname: "c.protonvpn.net",
						TCP: true, UDP: true, Keep: true,
					},
				},
			},
			expected: models.Servers{
				Version:   4,
				Timestamp: 100,
				Servers: []models.Server{
					{VPN: "openvpn", Country: "Canada", City: "Montreal", Hostname: "b.protonvpn.net", TCP: true, UDP: true},
					{
						VPN: "openvpn", Country: "Germany", City: "Berlin", Hostname: "c.protonvpn.net",
						TCP: true, UDP: true, Keep: true,
					},
					{VPN: "openvpn", Country: "USA", City: "Chicago", Hostname: "a.protonvpn.net", TCP: true, UDP: true, Keep: true},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			logger := NewMockLogger(ctrl)
			if testCase.logInfo != "" {
				logger.EXPECT().Info(testCase.logInfo)
			}
			if testCase.logWarn != "" {
				logger.EXPECT().Warn(testCase.logWarn)
			}

			s := &Storage{logger: logger}
			merged := s.mergeProviderServers(provider, testCase.hardcoded, testCase.persisted)

			assert.Equal(t, testCase.expected, merged)
		})
	}
}
