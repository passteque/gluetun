package utils

import (
	"errors"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
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
					UDPPorts: []uint16{15021},
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
				Port:     15021,
				Hostname: "name",
			}},
		},
		"OpenVPN server with x509": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021},
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
				Port:     15021,
				Hostname: "x509",
			}},
		},
		"OpenVPN server uses protocol-specific TCP port when no custom port set": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					TCP:      true,
					TCPPorts: []uint16{4433},
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, 8})},
					Hostname: "name",
				},
			},
			serverSelection: func() settings.ServerSelection {
				ss := settings.ServerSelection{}.WithDefaults(providers.Mullvad)
				ss.OpenVPN.Protocol = constants.TCP
				return ss
			}(),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{8, 8, 8, 8}),
				Protocol: constants.TCP,
				Port:     4433,
				Hostname: "name",
			}},
		},
		"OpenVPN server uses protocol-specific UDP port when no custom port set": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021},
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{9, 9, 9, 9})},
					Hostname: "name",
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:   NewConnectionDefaults(443, 1194, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{9, 9, 9, 9}),
				Protocol: constants.UDP,
				Port:     15021,
				Hostname: "name",
			}},
		},
		"OpenVPN explicit custom port overrides protocol-specific port": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021},
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{10, 10, 10, 10})},
					Hostname: "name",
				},
			},
			serverSelection: func() settings.ServerSelection {
				ss := settings.ServerSelection{}.WithDefaults(providers.Mullvad)
				*ss.OpenVPN.CustomPort = 1194
				return ss
			}(),
			defaults:   NewConnectionDefaults(443, 53, 58820),
			randSource: rand.NewSource(0),
			connections: []models.Connection{{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "name",
			}},
		},
		"server with IPv4 and IPv6": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					UDPPorts: []uint16{
						15021,
					},
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
			connections: []models.Connection{
				{
					Type:     vpn.OpenVPN,
					IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
					Protocol: constants.UDP,
					Port:     15021,
				},
			},
		},
		"server with IPv4 and IPv6 and ipv6 supported": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					UDPPorts: []uint16{
						15021,
					},
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
			connections: []models.Connection{
				{
					Type:     vpn.OpenVPN,
					IP:       netip.IPv6Unspecified(),
					Protocol: constants.UDP,
					Port:     15021,
				},
			},
		},
		"mixed servers": {
			filteredServers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021},
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
					OvpnX509: "ovpnx509",
				},
				{
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021},
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
				Port:     15021,
				Hostname: "ovpnx509",
			}, {
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{3, 3, 3, 3}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "hostname",
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

func Test_getPortForServer_InventoryPorts(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		server         models.Server
		protocol       string
		defaultTCPPort uint16
		defaultUDPPort uint16
		expectedPort   uint16
	}{
		"TCP uses inventory port": {
			server:         models.Server{TCPPorts: []uint16{80, 443}},
			protocol:       constants.TCP,
			defaultTCPPort: 443,
			defaultUDPPort: 15021,
			expectedPort:   80,
		},
		"UDP uses inventory port": {
			server:         models.Server{UDPPorts: []uint16{15021, 1194}},
			protocol:       constants.UDP,
			defaultTCPPort: 443,
			defaultUDPPort: 15021,
			expectedPort:   15021,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			port := getPortForServer(testCase.server, testCase.protocol,
				testCase.defaultTCPPort, testCase.defaultUDPPort)

			assert.Equal(t, testCase.expectedPort, port)
		})
	}
}
