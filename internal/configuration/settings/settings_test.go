package settings

import (
	"net/netip"
	"testing"

	constvpn "github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mapSource map[string]string

func (s mapSource) String() string { return "test map" }

func (s mapSource) Get(key string) (value string, isSet bool) {
	value, isSet = s[key]
	return value, isSet
}

func (s mapSource) KeyTransform(key string) string { return key }

type noopWarner struct{}

func (noopWarner) Warn(string) {}

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
|   |       ├── Selection mode: random
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
|       └── Block ads: no
├── Firewall settings:
|   ├── Enabled: yes
|   └── Iptables settings:
|       └── Log level: INFO
├── Log settings:
|   └── Log level: INFO
├── IPv6 settings:
|   └── Check addresses:
|       ├── [2001:4860:4860::8888]:53
|       └── [2606:4700:4700::1111]:53
├── Metrics settings:
|   └── Type: noop
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
├── SOCKS5 proxy server settings:
|   └── Enabled: no
├── Shadowsocks server settings:
|   └── Enabled: no
├── HTTP proxy settings:
|   └── Enabled: no
├── Control server settings:
|   ├── Listening address: :8000
|   ├── Logging: yes
|   └── Authentication file path: /gluetun/auth/config.toml
├── Storage settings:
|   └── Servers directory path: /gluetun/servers/
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

func Test_Settings_applyVPNDNS(t *testing.T) {
	t.Parallel()

	const vpnDNS = "10.0.0.1:53"
	testCases := map[string]struct {
		settings Settings
		dns      DNS
	}{
		"amneziawg_config_dns": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.AmneziaWg,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
			},
			dns: DNS{
				UpstreamType:           DNSUpstreamTypePlain,
				UpstreamPlainAddresses: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
			},
		},
		"explicit_plain_uses_config_addresses": {
			settings: Settings{
				VPN: VPN{Type: constvpn.AmneziaWg, AmneziaWg: AmneziaWg{
					DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
				}},
				DNS: DNS{UpstreamType: DNSUpstreamTypePlain},
			},
			dns: DNS{
				UpstreamType:           DNSUpstreamTypePlain,
				UpstreamPlainAddresses: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
			},
		},
		"explicit_dns_takes_precedence": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.AmneziaWg,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
				DNS: DNS{
					UpstreamType: DNSUpstreamTypeDoh,
					UpstreamPlainAddresses: []netip.AddrPort{
						netip.MustParseAddrPort("1.1.1.1:53"),
					},
				},
			},
			dns: DNS{
				UpstreamType: DNSUpstreamTypeDoh,
				UpstreamPlainAddresses: []netip.AddrPort{
					netip.MustParseAddrPort("1.1.1.1:53"),
				},
			},
		},
		"explicit_doh_takes_precedence": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.AmneziaWg,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
				DNS: DNS{UpstreamType: DNSUpstreamTypeDoh},
			},
			dns: DNS{UpstreamType: DNSUpstreamTypeDoh},
		},
		"explicit_dot_takes_precedence": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.AmneziaWg,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
				DNS: DNS{UpstreamType: DNSUpstreamTypeDot},
			},
			dns: DNS{UpstreamType: DNSUpstreamTypeDot},
		},
		"explicit_resolvers_take_precedence": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.AmneziaWg,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
				DNS: DNS{Providers: []string{"cloudflare"}},
			},
			dns: DNS{Providers: []string{"cloudflare"}},
		},
		"other_vpn_type_ignores_amneziawg_dns": {
			settings: Settings{
				VPN: VPN{
					Type: constvpn.Wireguard,
					AmneziaWg: AmneziaWg{
						DNSServers: []netip.AddrPort{netip.MustParseAddrPort(vpnDNS)},
					},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := testCase.settings
			settings.applyVPNDNS()

			assert.Equal(t, testCase.dns, settings.DNS)
		})
	}
}

func Test_Settings_Read_amneziaWGConfigFields(t *testing.T) {
	t.Parallel()

	settingsReader := reader.New(reader.Settings{
		Sources: []reader.Source{mapSource{
			"VPN_TYPE":              constvpn.AmneziaWg,
			"AMNEZIAWG_ALLOWED_IPS": "0.0.0.0/0,::/0",
			"AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL": "25-35",
			"AMNEZIAWG_RANDOM_TRAILERS":               "on",
			"AMNEZIAWG_DISABLE_COOKIES":               "on",
			"AMNEZIAWG_DNS":                           "1.1.1.1,8.8.8.8",
		}},
	})
	settings := Settings{}

	err := settings.Read(settingsReader, noopWarner{})
	require.NoError(t, err)
	settings.SetDefaults()

	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}, settings.VPN.AmneziaWg.Wireguard.AllowedIPs)
	assert.Equal(t, [2]uint32{25, 35}, *settings.VPN.AmneziaWg.PersistentKeepaliveInterval)
	assert.Zero(t, *settings.VPN.AmneziaWg.Wireguard.PersistentKeepaliveInterval)
	assert.True(t, *settings.VPN.AmneziaWg.RandomTrailers)
	assert.True(t, *settings.VPN.AmneziaWg.DisableCookies)
	assert.Equal(t, DNSUpstreamTypePlain, settings.DNS.UpstreamType)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:53"),
	}, settings.DNS.UpstreamPlainAddresses)
}
