package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_OpenVPNSelection_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider         string
		protocol         string
		customPort       uint16
		endpointIP       netip.Addr
		endpointHostname *string
		errMessage       string
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
		"endpoint_hostname_only": {
			provider:         providers.Custom,
			endpointHostname: new("myhost.dyndns.org"),
		},
		"endpoint_ip_and_hostname_mutually_exclusive": {
			provider:         providers.Custom,
			endpointIP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
			endpointHostname: new("myhost.dyndns.org"),
			errMessage:       "endpoint IP and endpoint hostname are mutually exclusive",
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
			if testCase.endpointIP.IsValid() {
				selection.EndpointIP = testCase.endpointIP
			}
			selection.EndpointHostname = testCase.endpointHostname

			err := selection.validate(testCase.provider)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
		})
	}
}
