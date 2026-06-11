package custom

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func intPtr(n int) *int          { return &n }
func uint16Ptr(n uint16) *uint16 { return &n }
func stringPtr(s string) *string { return &s }

func Test_modifyConfig(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		lines         []string
		settings      settings.OpenVPN
		connection    models.Connection
		ipv6Supported bool
		modified      []string
	}{
		"mixed": {
			lines: []string{
				"up bla",
				"proto tcp",
				"remote 5.5.5.5",
				"cipher bla",
				"",
				"tun-ipv6",
				"keep me here",
				"auth bla",
			},
			settings: settings.OpenVPN{
				User:        stringPtr("user"),
				Ciphers:     []string{"cipher"},
				Auth:        stringPtr("sha512"),
				MSSFix:      uint16Ptr(1000),
				ProcessUser: "procuser",
				Interface:   "tun3",
				Verbosity:   intPtr(0),
			}.WithDefaults(providers.Custom),
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     1194,
				Protocol: constants.UDP,
			},
			ipv6Supported: false,
			modified: []string{
				"up bla",
				"keep me here",
				"proto udp",
				"remote 1.2.3.4 1194",
				"dev tun3",
				"mute-replay-warnings",
				"auth-nocache",
				"pull-filter ignore \"auth-token\"",
				"auth-retry nointeract",
				"suppress-timestamps",
				"hand-window 20",
				"auth-user-pass /etc/openvpn/auth.conf",
				"verb 0",
				"data-ciphers-fallback cipher",
				"data-ciphers cipher",
				"auth sha512",
				"mssfix 1000",
				"pull-filter ignore \"route-ipv6\"",
				"pull-filter ignore \"ifconfig-ipv6\"",
				"user procuser",
				"persist-tun",
				"persist-key",
				"",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			modified := modifyConfig(testCase.lines,
				testCase.connection, testCase.settings, testCase.ipv6Supported)

			assert.Equal(t, testCase.modified, modified)
		})
	}
}
