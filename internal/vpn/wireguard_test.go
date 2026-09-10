package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
)

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
				GSO:                         ptrTo(true),
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
				GSO:                         ptrTo(true),
			},
		},
		"gso_disabled": {
			connection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{5, 6, 7, 8}),
				Port:   58820,
				PubKey: "public",
			},
			userSettings: settings.Wireguard{
				PrivateKey:                  ptrTo("private"),
				PreSharedKey:                ptrTo(""),
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				MTU:                         ptrTo(uint32(0)),
				GSO:                         ptrTo(false),
			},
			ipv6Supported: false,
			settings: wireguard.Settings{
				InterfaceName: "wg0",
				PrivateKey:    "private",
				PublicKey:     "public",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 58820),
				Addresses:     []netip.Prefix{},
				AllowedIPs:    []netip.Prefix{},
				RulePriority:  101,
				IPv6:          ptrTo(false),
				MTU:           1320,
				GSO:           ptrTo(false),
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

type mockProvider struct {
	connection models.Connection
	getConnErr error
}

func (m mockProvider) GetConnection(settings.ServerSelection, bool) (models.Connection, error) {
	return m.connection, m.getConnErr
}

func (m mockProvider) OpenVPNConfig(models.Connection, settings.OpenVPN, bool) []string {
	return nil
}

func (m mockProvider) Name() string {
	return "mock"
}

func (m mockProvider) FetchServers(context.Context, int) ([]models.Server, error) {
	return nil, nil
}

type mockWireguardProvider struct {
	mockProvider
	wireguardConfig func(ctx context.Context, connection *models.Connection,
		settings settings.VPN, wireguardSettings wireguard.Settings,
		fw common.Firewall) (wireguard.Settings, error)
}

func (m mockWireguardProvider) WireguardConfig(ctx context.Context, connection *models.Connection,
	settings settings.VPN, wireguardSettings wireguard.Settings,
	fw common.Firewall,
) (wireguard.Settings, error) {
	return m.wireguardConfig(ctx, connection, settings, wireguardSettings, fw)
}

type mockFirewall struct {
	setConnErr error
}

func (m mockFirewall) SetVPNConnection(context.Context, models.Connection, string) error {
	return m.setConnErr
}

func (m mockFirewall) SetAllowedPort(context.Context, uint16, string) error { return nil }
func (m mockFirewall) RemoveAllowedPort(context.Context, uint16) error      { return nil }
func (m mockFirewall) AcceptOutput(context.Context, string, string, netip.Addr, uint16, bool) error {
	return nil
}
func (m mockFirewall) TempDropOutputTCPRST(context.Context, netip.AddrPort, netip.AddrPort, int) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

type mockLogger struct{}

func (m mockLogger) Debug(string)                           {}
func (m mockLogger) Debugf(string, ...interface{})          {}
func (m mockLogger) Info(string)                            {}
func (m mockLogger) Warn(string)                            {}
func (m mockLogger) Error(string)                           {}
func (m mockLogger) Errorf(string, ...interface{})          {}

func Test_setupWireguard(t *testing.T) {
	t.Parallel()

	validPrivKey := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	validPubKey := "1/5n4w0b6K3m1h4/7h0f+z2V7h0b6K3m1h4/7h0f+z0="

	testCases := map[string]struct {
		providerConf       mockWireguardProvider
		isWireguardConfig  bool
		settings           settings.VPN
		firewall           mockFirewall
		expectedConnection models.Connection
		expectedErr        error
	}{
		"standard provider success": {
			providerConf: mockWireguardProvider{
				mockProvider: mockProvider{
					connection: models.Connection{
						IP:     netip.AddrFrom4([4]byte{1, 2, 3, 4}),
						Port:   51820,
						PubKey: validPubKey,
					},
				},
			},
			isWireguardConfig: false,
			settings: settings.VPN{
				Wireguard: settings.Wireguard{
					PrivateKey:                  ptrTo(validPrivKey),
					PreSharedKey:                ptrTo(""),
					Addresses:                   []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32)},
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					MTU:                         ptrTo(uint32(0)),
					Implementation:              "auto",
					GSO:                         ptrTo(true),
				},
			},
			expectedConnection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:   51820,
				PubKey: validPubKey,
			},
		},
		"wireguard configer success": {
			providerConf: mockWireguardProvider{
				mockProvider: mockProvider{
					connection: models.Connection{
						IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
						Port:       1337,
						ServerName: "bahamas413",
					},
				},
				wireguardConfig: func(_ context.Context, conn *models.Connection,
					_ settings.VPN, wgSettings wireguard.Settings, _ common.Firewall,
				) (wireguard.Settings, error) {
					wgSettings.PrivateKey = validPrivKey
					wgSettings.PublicKey = validPubKey
					wgSettings.Addresses = []netip.Prefix{
						netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32),
					}
					conn.PubKey = validPubKey
					return wgSettings, nil
				},
			},
			isWireguardConfig: true,
			settings: settings.VPN{
				Wireguard: settings.Wireguard{
					PrivateKey:                  ptrTo(""),
					PreSharedKey:                ptrTo(""),
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					MTU:                         ptrTo(uint32(0)),
					Implementation:              "auto",
					GSO:                         ptrTo(true),
				},
			},
			expectedConnection: models.Connection{
				IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
				Port:       1337,
				ServerName: "bahamas413",
				PubKey:     validPubKey,
			},
		},
		"wireguard configer error": {
			providerConf: mockWireguardProvider{
				mockProvider: mockProvider{
					connection: models.Connection{
						IP:         netip.AddrFrom4([4]byte{95, 181, 238, 98}),
						Port:       1337,
						ServerName: "bahamas413",
					},
				},
				wireguardConfig: func(context.Context, *models.Connection,
					settings.VPN, wireguard.Settings, common.Firewall,
				) (wireguard.Settings, error) {
					return wireguard.Settings{}, errors.New("auth failed")
				},
			},
			isWireguardConfig: true,
			settings: settings.VPN{
				Wireguard: settings.Wireguard{
					PrivateKey:                  ptrTo(""),
					PreSharedKey:                ptrTo(""),
					AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
					PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
					Interface:                   "wg0",
					MTU:                         ptrTo(uint32(0)),
					Implementation:              "auto",
					GSO:                         ptrTo(true),
				},
			},
			expectedErr: errors.New("configuring wireguard: auth failed"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var prov provider.Provider = testCase.providerConf.mockProvider
			if testCase.isWireguardConfig {
				prov = testCase.providerConf
			}

			netlinker := (NetLinker)(nil)
			fw := testCase.firewall
			const ipv6SupportLevel = netlink.IPv6Unsupported
			logger := mockLogger{}

			wireguarder, connection, err := setupWireguard(t.Context(), netlinker,
				fw, prov, testCase.settings, ipv6SupportLevel, logger)

			if testCase.expectedErr != nil {
				assert.Equal(t, testCase.expectedErr.Error(), err.Error())
				assert.Nil(t, wireguarder)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, wireguarder)
			assert.Equal(t, testCase.expectedConnection, connection)
		})
	}
}
