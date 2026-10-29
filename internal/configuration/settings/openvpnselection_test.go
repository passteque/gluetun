package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_OpenVPNSelection_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider   string
		protocol   string
		customPort uint16
		errMessage string
	}{
		"purevpn_udp_no_custom_port": {
			provider: providers.Purevpn,
		},
		"purevpn_tcp_no_custom_port": {
			provider: providers.Purevpn,
			protocol: constants.TCP,
		},
		// PureVPN server ports depend on the servers data, so any port is
		// accepted and servers not supporting it are filtered out.
		"purevpn_udp_custom_port_15021": {
			provider:   providers.Purevpn,
			customPort: 15021,
		},
		"purevpn_udp_custom_port_5565": {
			provider:   providers.Purevpn,
			customPort: 5565,
		},
		"purevpn_tcp_custom_port_8080": {
			provider:   providers.Purevpn,
			protocol:   constants.TCP,
			customPort: 8080,
		},
		"mullvad_udp_custom_port_allowed": {
			provider:   providers.Mullvad,
			customPort: 1194,
		},
		"mullvad_udp_custom_port_denied": {
			provider:   providers.Mullvad,
			customPort: 5565,
			errMessage: "custom endpoint port is not allowed: for VPN service provider mullvad",
		},
		"mullvad_tcp_custom_port_denied": {
			provider:   providers.Mullvad,
			protocol:   constants.TCP,
			customPort: 8080,
			errMessage: "custom endpoint port is not allowed: for VPN service provider mullvad",
		},
		"expressvpn_custom_port_denied": {
			provider:   providers.Expressvpn,
			customPort: 443,
			errMessage: "custom endpoint port is not allowed: for VPN service provider expressvpn",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := OpenVPNSelection{}
			selection.setDefaults(testCase.provider)
			if testCase.protocol != "" {
				selection.Protocol = testCase.protocol
			}
			selection.CustomPort = new(testCase.customPort)

			err := selection.validate(testCase.provider)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
