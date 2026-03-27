package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Settings_String(t *testing.T) {
	t.Parallel()

	withDefaults := func(s Settings) Settings {
		s.SetDefaults()
		return s
	}

	testCases := map[string]struct {
		settings Settings
		s        string
	}{
		"default settings": {
			settings: withDefaults(Settings{}),
			s: `Settings summary:
├── VPN settings:
|   ├── VPN provider settings:
|   |   ├── Name: private internet access
|   |   └── Server selection settings:
|   |       ├── VPN type: openvpn
|   |       └── OpenVPN server selection settings:
|   |           ├── Protocol: UDP
|   |           └── Private Internet Access encryption preset: strong
|   ├── OpenVPN settings:
|   |   ├── OpenVPN version: 2.6
|   |   ├── User: [not set]
|   |   ├── Password: [not set]
|   |   ├── Private Internet Access encryption preset: strong
|   |   ├── Network interface: tun0
|   |   ├── Run OpenVPN as: root
|   |   └── Verbosity level: 1
|   └── Path MTU discovery:
|       ├── ICMP addresses:
|       |   ├── 1.1.1.1
|       |   └── 8.8.8.8
|       └── TCP addresses:
|           ├── 1.1.1.1:53
|           ├── 8.8.8.8:53
|           ├── 1.1.1.1:443
|           ├── 8.8.8.8:443
|           ├── [2606:4700:4700::1111]:53
|           ├── [2001:4860:4860::8888]:53
|           ├── [2606:4700:4700::1111]:443
|           └── [2001:4860:4860::8888]:443
├── DNS settings:
|   ├── Upstream resolver type: dot
|   ├── Upstream resolvers:
|   |   └── Cloudflare
|   ├── Caching: yes
|   ├── IPv6: no
|   ├── Update period: every 24h0m0s
|   └── DNS filtering settings:
|       ├── Block malicious: yes
|       ├── Block ads: no
|       └── Block surveillance: yes
├── Firewall settings:
|   ├── Enabled: yes
|   └── Iptables settings:
|       └── Log level: INFO
├── Log settings:
|   └── Log level: INFO
├── Health settings:
|   ├── Server listening address: 127.0.0.1:9999
|   ├── Target addresses:
|   |   ├── cloudflare.com:443
|   |   └── github.com:443
|   ├── Small health check type: ICMP echo request
|   |   └── ICMP target IPs:
|   |       ├── 1.1.1.1
|   |       └── 8.8.8.8
|   └── Restart VPN on healthcheck failure: yes
├── Shadowsocks server settings:
|   └── Enabled: no
├── HTTP proxy settings:
|   └── Enabled: no
├── Control server settings:
|   ├── Listening address: :8000
|   ├── Logging: yes
|   └── Authentication file path: /gluetun/auth/config.toml
├── Storage settings:
|   └── Filepath: /gluetun/servers.json
├── OS Alpine settings:
|   ├── Process UID: 1000
|   └── Process GID: 1000
├── Public IP settings:
|   ├── IP file path: /tmp/gluetun/ip
|   ├── Public IP data base API: ipinfo
|   └── Public IP data backup APIs:
|       ├── cloudflare
|       ├── ifconfigco
|       └── ip2location
└── Version settings:
    └── Enabled: yes`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := testCase.settings.String()

			assert.Equal(t, testCase.s, s)
		})
	}
}
