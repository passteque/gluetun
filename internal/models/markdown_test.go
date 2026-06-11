package models

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
)

func Test_Servers_ToMarkdown(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider   string
		servers    Servers
		formatted  string
		errMessage string
	}{
		"unsupported_provider": {
			provider:   "unsupported",
			errMessage: "getting markdown headers: markdown headers not defined: for unsupported",
		},
		providers.Cyberghost: {
			provider: providers.Cyberghost,
			servers: Servers{
				Servers: []Server{
					{Country: "a", UDP: true, Hostname: "xa"},
					{Country: "b", TCP: true, Hostname: "xb"},
				},
			},
			formatted: "| Country | Hostname | TCP | UDP |\n" +
				"| --- | --- | --- | --- |\n" +
				"| a | `xa` | ❌ | ✅ |\n" +
				"| b | `xb` | ✅ | ❌ |\n",
		},
		providers.Fastestvpn: {
			provider: providers.Fastestvpn,
			servers: Servers{
				Servers: []Server{
					{Country: "a", Hostname: "xa", VPN: vpn.OpenVPN, TCP: true},
					{Country: "b", Hostname: "xb", VPN: vpn.OpenVPN, UDP: true},
				},
			},
			formatted: "| Country | Hostname | VPN | TCP | UDP |\n" +
				"| --- | --- | --- | --- | --- |\n" +
				"| a | `xa` | openvpn | ✅ | ❌ |\n" +
				"| b | `xb` | openvpn | ❌ | ✅ |\n",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			markdown, err := testCase.servers.toMarkdown(testCase.provider)

			assert.Equal(t, testCase.formatted, markdown)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
