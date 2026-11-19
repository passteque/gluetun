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

	errTest := errors.New("test error")

	testCases := map[string]struct {
		provider        string
		filteredServers []models.Server
		filterError     error
		serverSelection settings.ServerSelection
		defaults        ConnectionDefaults
		ipv6Supported   bool
		randSource      rand.Source
		connection      models.Connection
		errWrapped      error
		errMessage      string
	}{
		"storage filter error": {
			filterError: errTest,
			errWrapped:  errTest,
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
			errWrapped: ErrNoConnectionToPickFrom,
			errMessage: "no connection to pick from",
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
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "name",
			},
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
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "x509",
			},
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
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
			},
		},
		"server with IPv4 and IPv6 and ipv6 supported": {
			filteredServers: []models.Server{
				{
					VPN: vpn.OpenVPN,
					UDP: true,
					IPs: []netip.Addr{
						netip.IPv6Unspecified(),
						netip.AddrFrom4([4]byte{1, 1, 1, 1}),
					},
				},
			},
			serverSelection: settings.ServerSelection{}.
				WithDefaults(providers.Mullvad),
			defaults:      NewConnectionDefaults(443, 1194, 58820),
			ipv6Supported: true,
			randSource:    rand.NewSource(0),
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.IPv6Unspecified(),
				Protocol: constants.UDP,
				Port:     1194,
			},
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
					VPN:      vpn.Wireguard,
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{2, 2, 2, 2})},
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
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Protocol: constants.UDP,
				Port:     1194,
				Hostname: "ovpnx509",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := common.NewMockStorage(ctrl)
			storage.EXPECT().
				FilterServers(testCase.provider, testCase.serverSelection).
				Return(testCase.filteredServers, testCase.filterError)

			connection, err := GetConnection(testCase.provider, storage,
				testCase.serverSelection, testCase.defaults, testCase.ipv6Supported,
				testCase.randSource)

			assert.Equal(t, testCase.connection, connection)
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

// Test_GetConnection_serverPorts covers the server defined ports used to build
// the connections: since the PureVPN data revamp a single server can expose
// several OpenVPN ports, and a server not supporting the custom port set must
// not be selected.
func Test_GetConnection_serverPorts(t *testing.T) {
	t.Parallel()

	tcpSelection := settings.ServerSelection{}.WithDefaults(providers.Purevpn)
	tcpSelection.OpenVPN.Protocol = constants.TCP

	customPortSelection := settings.ServerSelection{}.WithDefaults(providers.Purevpn)
	customPortSelection.OpenVPN.Protocol = constants.TCP
	customPort := uint16(4433)
	customPortSelection.OpenVPN.CustomPort = &customPort

	unsupportedPortSelection := settings.ServerSelection{}.WithDefaults(providers.Purevpn)
	unsupportedPortSelection.OpenVPN.Protocol = constants.TCP
	unsupportedPort := uint16(1234)
	unsupportedPortSelection.OpenVPN.CustomPort = &unsupportedPort

	ip := netip.AddrFrom4([4]byte{1, 1, 1, 1})

	testCases := map[string]struct {
		server          models.Server
		serverSelection settings.ServerSelection
		defaults        ConnectionDefaults
		expectedPorts   []uint16
		errMessage      string
	}{
		"udp ports of the server are used": {
			server: models.Server{
				VPN:      vpn.OpenVPN,
				IPs:      []netip.Addr{ip},
				UDPPorts: []uint16{15021, 1194},
			},
			serverSelection: settings.ServerSelection{}.WithDefaults(providers.Purevpn),
			defaults:        NewConnectionDefaults(443, 443, 1382),
			expectedPorts:   []uint16{1194, 15021},
		},
		"tcp ports of the server are used": {
			server: models.Server{
				VPN:      vpn.OpenVPN,
				IPs:      []netip.Addr{ip},
				TCPPorts: []uint16{4433},
			},
			serverSelection: tcpSelection,
			defaults:        NewConnectionDefaults(443, 443, 1382),
			expectedPorts:   []uint16{4433},
		},
		"custom port supported by the server is used": {
			server: models.Server{
				VPN:      vpn.OpenVPN,
				IPs:      []netip.Addr{ip},
				TCPPorts: []uint16{443, 4433},
			},
			serverSelection: customPortSelection,
			defaults:        NewConnectionDefaults(443, 443, 1382),
			expectedPorts:   []uint16{4433},
		},
		"custom port unsupported by the server is an error": {
			server: models.Server{
				VPN:      vpn.OpenVPN,
				IPs:      []netip.Addr{ip},
				TCPPorts: []uint16{443},
			},
			serverSelection: unsupportedPortSelection,
			defaults:        NewConnectionDefaults(443, 443, 1382),
			errMessage: "no connection to pick from: no server supports the custom" +
				" port 1234 out of 1 filtered servers",
		},
		"no server port falls back on the provider default port": {
			server: models.Server{
				VPN: vpn.OpenVPN,
				IPs: []netip.Addr{ip},
			},
			serverSelection: settings.ServerSelection{}.WithDefaults(providers.Purevpn),
			defaults:        NewConnectionDefaults(443, 443, 1382),
			expectedPorts:   []uint16{443},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			storage := common.NewMockStorage(ctrl)
			storage.EXPECT().
				FilterServers(providers.Purevpn, testCase.serverSelection).
				Return([]models.Server{testCase.server}, nil)

			connection, err := GetConnection(providers.Purevpn, storage,
				testCase.serverSelection, testCase.defaults, true, rand.NewSource(0))

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, ip, connection.IP)
			assert.Contains(t, testCase.expectedPorts, connection.Port)
		})
	}
}
