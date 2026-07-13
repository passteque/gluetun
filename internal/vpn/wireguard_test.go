package vpn

import (
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_buildRegisteredWireguardSettings(t *testing.T) {
	t.Parallel()

	registeredPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	registration := models.WireguardConnection{
		Connection: models.Connection{
			IP:     netip.MustParseAddr("198.51.100.3"),
			Port:   1337,
			PubKey: serverPrivateKey.PublicKey().String(),
		},
		PrivateKey: registeredPrivateKey.String(),
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.13.161.2/32")},
	}
	zeroKeepalive := time.Duration(0)
	userSettings := settings.Wireguard{
		PrivateKey:                  new("unused-user-private-key"),
		PreSharedKey:                new(""),
		AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		PersistentKeepaliveInterval: &zeroKeepalive,
		Interface:                   "tun0",
		MTU:                         new(uint32(1320)),
	}

	wireguardSettings := buildRegisteredWireguardSettings(registration, userSettings, false)

	assert.Equal(t, registeredPrivateKey.String(), wireguardSettings.PrivateKey)
	assert.Equal(t, registration.Connection.PubKey, wireguardSettings.PublicKey)
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.3:1337"), wireguardSettings.Endpoint)
	assert.Equal(t, registration.Addresses, wireguardSettings.Addresses)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, wireguardSettings.AllowedIPs)
	assert.Equal(t, 25*time.Second, wireguardSettings.PersistentKeepaliveInterval)
}

func Test_buildWireguardSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		connection    models.Connection
		userSettings  settings.Wireguard
		ipv6Supported bool
		settings      wireguard.Settings
	}{
		"some_settings": {
			connection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:   51821,
				PubKey: "public",
			},
			userSettings: settings.Wireguard{
				PrivateKey:   ptrTo("private"),
				PreSharedKey: ptrTo("pre-shared"),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				PersistentKeepaliveInterval: ptrTo(time.Hour),
				Interface:                   "wg1",
				MTU:                         ptrTo(uint32(1000)),
			},
			ipv6Supported: false,
			settings: wireguard.Settings{
				InterfaceName: "wg1",
				PrivateKey:    "private",
				PublicKey:     "public",
				PreSharedKey:  "pre-shared",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51821),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				},
				PersistentKeepaliveInterval: time.Hour,
				RulePriority:                101,
				IPv6:                        ptrTo(false),
				MTU:                         1000,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := buildWireguardSettings(testCase.connection,
				testCase.userSettings, testCase.ipv6Supported)

			assert.Equal(t, testCase.settings, settings)
		})
	}
}
