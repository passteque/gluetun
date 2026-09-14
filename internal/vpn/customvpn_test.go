package vpn

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
)

func Test_customVPNConnection(t *testing.T) {
	t.Parallel()

	endpointIP := netip.MustParseAddr("1.2.3.4")

	testCases := map[string]struct {
		settings   settings.VPN
		serverName string
	}{
		"no server name": {
			settings: settings.VPN{
				CustomVPN: settings.CustomVPN{
					EndpointIP:       endpointIP,
					EndpointPort:     1194,
					EndpointProtocol: "udp",
				},
			},
		},
		"first server name is carried": {
			settings: settings.VPN{
				CustomVPN: settings.CustomVPN{
					EndpointIP:       endpointIP,
					EndpointPort:     1194,
					EndpointProtocol: "udp",
				},
				Provider: settings.Provider{
					ServerSelection: settings.ServerSelection{
						Names: []string{"ca_toronto", "ca_montreal"},
					},
				},
			},
			serverName: "ca_toronto",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			connection := customVPNConnection(testCase.settings)

			assert.Equal(t, vpn.Custom, connection.Type)
			assert.Equal(t, endpointIP, connection.IP)
			assert.Equal(t, uint16(1194), connection.Port)
			assert.Equal(t, "udp", connection.Protocol)
			assert.Equal(t, testCase.serverName, connection.ServerName)
			assert.True(t, connection.PortForward,
				"port forwarding is not bound to the VPN protocol, so the "+
					"custom type must not opt out of it")
		})
	}
}
