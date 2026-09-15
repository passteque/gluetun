package tunstats

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
)

func Test_resolveInterfaceName(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnSettings settings.VPN
		expected    string
	}{
		"openvpn": {
			vpnSettings: settings.VPN{
				Type:    vpn.OpenVPN,
				OpenVPN: settings.OpenVPN{Interface: "tun0"},
			},
			expected: "tun0",
		},
		"openvpn_custom_interface": {
			vpnSettings: settings.VPN{
				Type:    vpn.OpenVPN,
				OpenVPN: settings.OpenVPN{Interface: "tun1"},
			},
			expected: "tun1",
		},
		"wireguard": {
			vpnSettings: settings.VPN{
				Type:      vpn.Wireguard,
				Wireguard: settings.Wireguard{Interface: "wg0"},
			},
			expected: "wg0",
		},
		"amneziawg": {
			vpnSettings: settings.VPN{
				Type: vpn.AmneziaWg,
				AmneziaWg: settings.AmneziaWg{
					Wireguard: settings.Wireguard{Interface: "awg0"},
				},
			},
			expected: "awg0",
		},
		"openvpn_empty_interface": {
			vpnSettings: settings.VPN{
				Type:    vpn.OpenVPN,
				OpenVPN: settings.OpenVPN{Interface: ""},
			},
			expected: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected, resolveInterfaceName(testCase.vpnSettings))
		})
	}

	t.Run("unknown_type", func(t *testing.T) {
		t.Parallel()

		assert.PanicsWithValue(t, "unknown VPN type: unknown", func() {
			_ = resolveInterfaceName(settings.VPN{Type: "unknown"})
		})
	})
}
