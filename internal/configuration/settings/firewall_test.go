package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
)

func Test_Firewall_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		firewall   Firewall
		errMessage string
	}{
		"empty": {
			errMessage: "iptables settings: log level: level is not recognized: ",
		},
		"zero_vpn_input_port": {
			firewall: Firewall{
				VPNInputPorts: []uint16{0},
			},
			errMessage: "VPN input ports: cannot have a zero port",
		},
		"zero_input_port": {
			firewall: Firewall{
				InputPorts: []uint16{0},
			},
			errMessage: "input ports: cannot have a zero port",
		},
		"unspecified_outbound_subnet": {
			firewall: Firewall{
				OutboundSubnets: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
			errMessage: "outbound subnet has an unspecified address: 0.0.0.0/0",
		},
		"public_outbound_subnet": {
			firewall: Firewall{
				Iptables: Iptables{LogLevel: log.LevelInfo.String()},
				OutboundSubnets: []netip.Prefix{
					netip.MustParsePrefix("1.2.3.4/32"),
				},
			},
		},
		"valid_settings": {
			firewall: Firewall{
				Iptables:      Iptables{LogLevel: log.LevelInfo.String()},
				VPNInputPorts: []uint16{100, 101},
				InputPorts:    []uint16{200, 201},
				OutboundSubnets: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("10.10.1.1/32"),
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.firewall.validate()

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
