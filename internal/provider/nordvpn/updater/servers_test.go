package updater

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractServers(t *testing.T) {
	t.Parallel()

	// Trimmed from the https://api.nordvpn.com/v2/servers response, with the
	// fields read by the updater only.
	const dataJSON = `{
		"groups": [
			{"id": 9, "identifier": "legacy_dedicated_ip", "title": "Dedicated IP",
				"type": {"identifier": "legacy_group_category"}},
			{"id": 11, "identifier": "legacy_standard", "title": "Standard VPN servers",
				"type": {"identifier": "legacy_group_category"}},
			{"id": 15, "identifier": "legacy_p2p", "title": "P2P",
				"type": {"identifier": "legacy_group_category"}},
			{"id": 21, "identifier": "the_americas", "title": "The Americas",
				"type": {"identifier": "regions"}}
		],
		"services": [
			{"id": 1, "identifier": "vpn"},
			{"id": 5, "identifier": "proxy"}
		],
		"locations": [
			{"id": 269, "country": {"name": "Canada",
				"city": {"name": "Toronto"}}},
			{"id": 4331, "country": {"name": "Canada",
				"city": {"name": "Calgary"}}}
		],
		"technologies": [
			{"id": 3, "identifier": "openvpn_udp"},
			{"id": 5, "identifier": "openvpn_tcp"},
			{"id": 35, "identifier": "wireguard_udp"},
			{"id": 42, "identifier": "openvpn_dedicated_udp"},
			{"id": 45, "identifier": "openvpn_dedicated_tcp"}
		]
	}`
	var data serversData
	err := json.Unmarshal([]byte(dataJSON), &data)
	require.NoError(t, err)
	groups, services, locations, technologies := data.idToData()

	testCases := map[string]struct {
		serverJSON string
		servers    []models.Server
		warnings   []string
	}{
		"dedicated_IP_server": {
			serverJSON: `{
				"name": "Canada #1700",
				"hostname": "ca1700.nordvpn.com",
				"status": "online",
				"location_ids": [269],
				"group_ids": [9, 21],
				"service_ids": [1],
				"technologies": [
					{"id": 3, "status": "online"},
					{"id": 42, "status": "online"},
					{"id": 45, "status": "online"},
					{"id": 35, "status": "online",
						"metadata": [{"name": "public_key", "value": "eh1aNcEknmlxkuXmwW4+pXl7jsJ+85xIqt0x5q8cdww="}]}
				],
				"ips": [{"type": "entry", "ip": {"ip": "154.47.17.23"}}]
			}`,
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "Canada",
					Region:     "The Americas",
					City:       "Toronto",
					Categories: []string{"Dedicated IP"},
					Dedicated:  true,
					Number:     1700,
					Hostname:   "ca1700.nordvpn.com",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("154.47.17.23")},
				},
				{
					VPN:        vpn.Wireguard,
					Country:    "Canada",
					Region:     "The Americas",
					City:       "Toronto",
					Categories: []string{"Dedicated IP"},
					Dedicated:  true,
					Number:     1700,
					Hostname:   "ca1700.nordvpn.com",
					WgPubKey:   "eh1aNcEknmlxkuXmwW4+pXl7jsJ+85xIqt0x5q8cdww=",
					IPs:        []netip.Addr{netip.MustParseAddr("154.47.17.23")},
				},
			},
		},
		"dedicated_IP_server_advertising_only_standard_technologies": {
			serverJSON: `{
				"name": "Canada #1701",
				"hostname": "ca1701.nordvpn.com",
				"status": "online",
				"location_ids": [269],
				"group_ids": [9, 21],
				"service_ids": [1],
				"technologies": [
					{"id": 3, "status": "online"},
					{"id": 5, "status": "online"}
				],
				"ips": [{"type": "entry", "ip": {"ip": "154.47.17.24"}}]
			}`,
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "Canada",
					Region:     "The Americas",
					City:       "Toronto",
					Categories: []string{"Dedicated IP"},
					Dedicated:  true,
					Number:     1701,
					Hostname:   "ca1701.nordvpn.com",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("154.47.17.24")},
				},
			},
		},
		"standard_server": {
			serverJSON: `{
				"name": "Canada #1937",
				"hostname": "ca1937.nordvpn.com",
				"status": "online",
				"location_ids": [4331],
				"group_ids": [11, 15, 21],
				"service_ids": [1],
				"technologies": [
					{"id": 3, "status": "online"},
					{"id": 5, "status": "online"}
				],
				"ips": [{"type": "entry", "ip": {"ip": "186.247.35.1"}}]
			}`,
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "Canada",
					Region:     "The Americas",
					City:       "Calgary",
					Categories: []string{"Standard VPN servers", "P2P"},
					Number:     1937,
					Hostname:   "ca1937.nordvpn.com",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("186.247.35.1")},
				},
			},
		},
		"offline_server": {
			serverJSON: `{
				"name": "Canada #1702",
				"hostname": "ca1702.nordvpn.com",
				"status": "offline",
				"location_ids": [269],
				"group_ids": [9, 21],
				"service_ids": [1],
				"ips": [{"type": "entry", "ip": {"ip": "154.47.17.25"}}]
			}`,
			warnings: []string{"ignoring server Canada #1702: status is offline"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var jsonServer serverData
			err := json.Unmarshal([]byte(testCase.serverJSON), &jsonServer)
			require.NoError(t, err)

			servers, warnings := extractServers(jsonServer,
				groups, services, locations, technologies)

			assert.Equal(t, testCase.servers, servers)
			assert.Equal(t, testCase.warnings, warnings)
		})
	}
}
