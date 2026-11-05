package utils

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func uint16Ptr(n uint16) *uint16 { return &n }

func Test_getPorts(t *testing.T) {
	t.Parallel()

	const (
		defaultOpenVPNTCP = 443
		defaultOpenVPNUDP = 1194
		defaultWireguard  = 51820
	)

	testCases := map[string]struct {
		selection         settings.ServerSelection
		server            models.Server
		defaultOpenVPNTCP uint16
		defaultOpenVPNUDP uint16
		defaultWireguard  uint16
		ports             []uint16
		panics            string
	}{
		"default": {
			selection:         settings.ServerSelection{}.WithDefaults(""),
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			defaultWireguard:  defaultWireguard,
			ports:             []uint16{defaultOpenVPNUDP},
		},
		"OpenVPN UDP": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.UDP,
				},
			},
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			defaultWireguard:  defaultWireguard,
			ports:             []uint16{defaultOpenVPNUDP},
		},
		"OpenVPN UDP no default port defined": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.UDP,
				},
			},
			panics: "no default OpenVPN UDP port is defined!",
		},
		"OpenVPN TCP": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.TCP,
				},
			},
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			defaultWireguard:  defaultWireguard,
			ports:             []uint16{defaultOpenVPNTCP},
		},
		"OpenVPN TCP no default port defined": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.TCP,
				},
			},
			panics: "no default OpenVPN TCP port is defined!",
		},
		"OpenVPN custom port": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(1234),
					Protocol:   constants.UDP,
				},
			},
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			defaultWireguard:  defaultWireguard,
			ports:             []uint16{1234},
		},
		"OpenVPN_server_with_TCP_port": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.TCP,
				},
			},
			server: models.Server{
				VPN:      vpn.OpenVPN,
				TCP:      true,
				TCPPorts: []uint16{80},
			},
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			ports:             []uint16{80},
		},
		"OpenVPN_server_with_UDP_ports": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(0),
					Protocol:   constants.UDP,
				},
			},
			server: models.Server{
				VPN:      vpn.OpenVPN,
				UDP:      true,
				UDPPorts: []uint16{5565, 1210},
			},
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			ports:             []uint16{5565, 1210},
		},
		"OpenVPN_custom_port_supported_by_server": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(1210),
					Protocol:   constants.UDP,
				},
			},
			server: models.Server{
				VPN:      vpn.OpenVPN,
				UDP:      true,
				UDPPorts: []uint16{5565, 1210},
			},
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			ports:             []uint16{1210},
		},
		"OpenVPN_custom_port_not_supported_by_server": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(8080),
					Protocol:   constants.UDP,
				},
			},
			server: models.Server{
				VPN:      vpn.OpenVPN,
				UDP:      true,
				UDPPorts: []uint16{5565, 1210},
			},
			defaultOpenVPNUDP: defaultOpenVPNUDP,
		},
		"OpenVPN_custom_port_and_server_without_ports": {
			selection: settings.ServerSelection{
				VPN: vpn.OpenVPN,
				OpenVPN: settings.OpenVPNSelection{
					CustomPort: uint16Ptr(8080),
					Protocol:   constants.UDP,
				},
			},
			server: models.Server{
				VPN: vpn.OpenVPN,
				UDP: true,
			},
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			ports:             []uint16{8080},
		},
		"Wireguard": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(""),
			defaultWireguard: defaultWireguard,
			ports:            []uint16{defaultWireguard},
		},
		"Wireguard custom port": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
				Wireguard: settings.WireguardSelection{
					EndpointPort: uint16Ptr(1234),
				},
			},
			defaultWireguard: defaultWireguard,
			ports:            []uint16{1234},
		},
		"Wireguard no default port defined": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(""),
			panics: "no default Wireguard port is defined!",
		},
		"AmneziaWG": {
			selection: settings.ServerSelection{
				VPN: vpn.AmneziaWg,
			}.WithDefaults(""),
			defaultWireguard: defaultWireguard,
			ports:            []uint16{defaultWireguard},
		},
		"AmneziaWG_custom_port": {
			selection: settings.ServerSelection{
				VPN: vpn.AmneziaWg,
				Wireguard: settings.WireguardSelection{
					EndpointPort: uint16Ptr(1234),
				},
			},
			defaultWireguard: defaultWireguard,
			ports:            []uint16{1234},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			portsFor := func() []uint16 {
				return getPorts(testCase.selection, testCase.server,
					testCase.defaultOpenVPNTCP, testCase.defaultOpenVPNUDP,
					testCase.defaultWireguard)
			}

			if testCase.panics != "" {
				assert.PanicsWithValue(t, testCase.panics, func() { _ = portsFor() })
				return
			}

			assert.Equal(t, testCase.ports, portsFor())
		})
	}
}
