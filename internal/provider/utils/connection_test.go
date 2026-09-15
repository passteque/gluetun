package utils

import (
	"errors"
	"math/rand"
	"net/netip"
	"slices"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_GetConnection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider        string
		filteredServers []models.Server
		filterError     error
		serverSelection settings.ServerSelection
		defaults        ConnectionDefaults
		ipv6Supported   bool
		randSource      rand.Source
		connections     []models.Connection
		errMessage      string
	}{
		"storage filter error": {
			filterError: errors.New("test error"),
			connections: []models.Connection{{}},
			errMessage:  "filtering servers: test error",
		},
		"server without IPs": {
			filteredServers: []models.Server{
				{VPN: vpn.OpenVPN, UDP: true},
				{VPN: vpn.OpenVPN, UDP: true},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults: ConnectionDefaults{
				OpenVPNTCPPort: 1,
				OpenVPNUDPPort: 1,
				WireguardPort:  1,
			},
			connections: []models.Connection{{}},
			errMessage:  "no connection to pick from",
		},
		"OpenVPN server with hostname": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					Hostname: "name",
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "name",
			}},
		},
		"OpenVPN server with x509": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					Hostname: "hostname",
					OvpnX509: "x509",
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "x509",
			}},
		},
		"server with IPv4 and IPv6": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{1, 1, 1, 1}),
						// All IPv6 is ignored
						netip.IPv6Unspecified(),
						netip.IPv6Unspecified(),
						netip.IPv6Unspecified(),
						netip.IPv6Unspecified(),
						netip.IPv6Unspecified(),
					},
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
			}},
		},
		"server with IPv4 and IPv6 and ipv6 supported": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{1, 1, 1, 1}),
						netip.IPv6Unspecified(),
					},
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:      NewConnectionDefaults(443, 1194, 58820),
			ipv6Supported: true,
			randSource:    rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.IPv6Unspecified(),
				Protocol: constants.UDP,
				Port:     1194,
			}},
		},
		"mixed servers": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					OvpnX509: "ovpnx509",
				},
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{3, 3, 3, 3}),
						netip.AddrFrom16([16]byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), // ipv6 ignored
					},
					Hostname: "hostname",
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "ovpnx509",
			}, {
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{3, 3, 3, 3}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "hostname",
			}},
		},
		"ordered_selection_mode_picks_by_list_order": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{2, 2, 2, 1})},
					Hostname: "de-1",
					Country:  "Germany",
				},
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					Hostname: "pl-1",
					Country:  "Poland",
				},
			},
			serverSelection: settings.ServerSelection{
				VPN:       vpn.OpenVPN,
				Mode:      "ordered",
				Countries: []string{"Poland", "Germany"},
			}.WithDefaults(providers.Mullvad),
			defaults: NewConnectionDefaults(443, 1194, 58820),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "pl-1",
			}},
		},
		"ordered_selection_mode_narrowest_filter_list_takes_priority": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					Hostname: "pl-warsaw-1",
					Country:  "Poland",
					City:     "Warsaw",
				},
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{2, 2, 2, 1})},
					Hostname: "de-berlin-1",
					Country:  "Germany",
					City:     "Berlin",
				},
			},
			serverSelection: settings.ServerSelection{
				VPN:       vpn.OpenVPN,
				Mode:      "ordered",
				Countries: []string{"Germany", "Poland"},
				Cities:    []string{"Berlin", "Warsaw"},
			}.WithDefaults(providers.Mullvad),
			defaults: NewConnectionDefaults(443, 1194, 58820),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{2, 2, 2, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "de-berlin-1",
			}},
		},
		"ordered_selection_mode_prefers_IPv6_within_a_tier": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{1, 1, 1, 1}),
						netip.MustParseAddr("2001:db8::1"),
					},
					Hostname: "pl-1",
					Country:  "Poland",
				},
			},
			serverSelection: settings.ServerSelection{
				VPN:       vpn.OpenVPN,
				Mode:      "ordered",
				Countries: []string{"Poland"},
			}.WithDefaults(providers.Mullvad),
			defaults:      NewConnectionDefaults(443, 1194, 58820),
			ipv6Supported: true,
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.MustParseAddr("2001:db8::1"),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "pl-1",
			}},
		},
		"ordered_selection_mode_tier_takes_priority_over_IPv6": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.MustParseAddr("2001:db8::2")},
					Hostname: "de-1",
					Country:  "Germany",
				},
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					Hostname: "pl-1",
					Country:  "Poland",
				},
			},
			serverSelection: settings.ServerSelection{
				VPN:       vpn.OpenVPN,
				Mode:      "ordered",
				Countries: []string{"Poland", "Germany"},
			}.WithDefaults(providers.Mullvad),
			defaults:      NewConnectionDefaults(443, 1194, 58820),
			ipv6Supported: true,
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "pl-1",
			}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			connPicker := NewConnectionPicker()

			storage := common.NewMockStorage(ctrl)
			storage.EXPECT().
				FilterServers(testCase.provider, testCase.serverSelection).
				Return(testCase.filteredServers, testCase.filterError)

			connection, err := GetConnection(testCase.provider, storage,
				testCase.serverSelection, testCase.defaults, testCase.ipv6Supported,
				connPicker)

			assert.Contains(t, testCase.connections, connection)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test_GetConnection_ordered_selection_mode_fallback tests that
// with the ordered selection mode, connections are picked from
// the first filter list values, falling back to the next ones
// only once the previous ones are exhausted across (re)starts.
func Test_GetConnection_ordered_selection_mode_fallback(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	connPicker := NewConnectionPicker()

	servers := []models.Server{
		{
			VPN:      vpn.OpenVPN,
			UDP:      true,
			IPs:      []netip.Addr{netip.AddrFrom4([4]byte{2, 2, 2, 1})},
			Hostname: "de-1",
			Country:  "Germany",
		},
		{
			VPN:      vpn.OpenVPN,
			UDP:      true,
			IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
			Hostname: "pl-1",
			Country:  "Poland",
		},
		{
			VPN:      vpn.OpenVPN,
			UDP:      true,
			IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 2})},
			Hostname: "pl-2",
			Country:  "Poland",
		},
		{
			VPN:      vpn.OpenVPN,
			UDP:      true,
			IPs:      []netip.Addr{netip.AddrFrom4([4]byte{3, 3, 3, 1})},
			Hostname: "cz-1",
			Country:  "Czechia",
		},
	}
	selection := settings.ServerSelection{
		VPN:       vpn.OpenVPN,
		Mode:      "ordered",
		Countries: []string{"Poland", "Germany", "Czechia"},
	}.WithDefaults(providers.Mullvad)
	defaults := NewConnectionDefaults(443, 1194, 58820)

	storage := common.NewMockStorage(ctrl)
	storage.EXPECT().
		FilterServers("", selection).
		DoAndReturn(func(_ string, _ settings.ServerSelection) ([]models.Server, error) {
			// Mimic the real storage that deep copies servers.
			serversCopy := make([]models.Server, len(servers))
			for i, server := range servers {
				serverCopy := server
				serverCopy.IPs = slices.Clone(server.IPs)
				serversCopy[i] = serverCopy
			}
			return serversCopy, nil
		}).
		Times(4)

	expectedConnections := []models.Connection{
		{
			Type:     vpn.OpenVPN,
			IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
			Protocol: constants.UDP,
			Port:     1194,
			Hostname: "pl-1",
		},
		{
			Type:     vpn.OpenVPN,
			IP:       netip.AddrFrom4([4]byte{1, 1, 1, 2}),
			Protocol: constants.UDP,
			Port:     1194,
			Hostname: "pl-2",
		},
		{
			Type:     vpn.OpenVPN,
			IP:       netip.AddrFrom4([4]byte{2, 2, 2, 1}),
			Protocol: constants.UDP,
			Port:     1194,
			Hostname: "de-1",
		},
		{
			Type:     vpn.OpenVPN,
			IP:       netip.AddrFrom4([4]byte{3, 3, 3, 1}),
			Protocol: constants.UDP,
			Port:     1194,
			Hostname: "cz-1",
		},
	}

	for i := range 4 {
		connection, err := GetConnection("", storage, selection,
			defaults, false, connPicker)
		assert.NoError(t, err)
		assert.Equal(t, expectedConnections[i], connection)
	}
}
