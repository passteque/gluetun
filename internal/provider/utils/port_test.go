package utils

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
)

func uint16Ptr(n uint16) *uint16 { return &n }

func Test_GetPort(t *testing.T) {
	t.Parallel()

	const (
		defaultOpenVPNTCP = 443
		defaultOpenVPNUDP = 1194
		defaultWireguard  = 51820
	)

	testCases := map[string]struct {
		selection         settings.ServerSelection
		defaultOpenVPNTCP uint16
		defaultOpenVPNUDP uint16
		defaultWireguard  uint16
		port              uint16
		panics            string
	}{
		"default": {
			selection:         settings.ServerSelection{}.WithDefaults(""),
			defaultOpenVPNTCP: defaultOpenVPNTCP,
			defaultOpenVPNUDP: defaultOpenVPNUDP,
			defaultWireguard:  defaultWireguard,
			port:              defaultOpenVPNUDP,
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
			port:              defaultOpenVPNUDP,
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
			port:              defaultOpenVPNTCP,
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
				},
			},
			port: 1234,
		},
		"Wireguard": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(""),
			defaultWireguard: defaultWireguard,
			port:             defaultWireguard,
		},
		"Wireguard custom port": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
				Wireguard: settings.WireguardSelection{
					EndpointPort: uint16Ptr(1234),
				},
			},
			defaultWireguard: defaultWireguard,
			port:             1234,
		},
		"Wireguard no default port defined": {
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(""),
			panics: "no default Wireguard port is defined!",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if testCase.panics != "" {
				assert.PanicsWithValue(t, testCase.panics, func() {
					_ = getPort(testCase.selection,
						testCase.defaultOpenVPNTCP,
						testCase.defaultOpenVPNUDP,
						testCase.defaultWireguard)
				})
				return
			}

			port := getPort(testCase.selection,
				testCase.defaultOpenVPNTCP,
				testCase.defaultOpenVPNUDP,
				testCase.defaultWireguard)

			assert.Equal(t, testCase.port, port)
		})
	}
}
