package wireguard

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_makeDeviceConfig(t *testing.T) {
	t.Parallel()

	const (
		validKey1 = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
		validKey2 = "aPjc9US5ICB30D1P4glR9tO7bkB2Ga+KZiFqnoypBHk="
		validKey3 = "gFIW0lTmBYEucynoIg+XmeWckDUXTcC4Po5ijR5G+HM="
	)

	parseKey := func(t *testing.T, s string) *wgtypes.Key {
		t.Helper()
		key, err := wgtypes.ParseKey(s)
		require.NoError(t, err)
		return &key
	}

	intPtr := func(n int) *int { return &n }

	testCases := map[string]struct {
		settings Settings
		config   wgtypes.Config
		err      error
	}{
		"bad private key": {
			settings: Settings{
				PrivateKey: "bad key",
			},
			err: errors.New("cannot parse private key"),
		},
		"bad public key": {
			settings: Settings{
				PrivateKey: validKey1,
				PublicKey:  "bad key",
			},
			err: errors.New("cannot parse public key: bad key"),
		},
		"bad pre-shared key": {
			settings: Settings{
				PrivateKey:   validKey1,
				PublicKey:    validKey2,
				PreSharedKey: "bad key",
			},
			err: errors.New("cannot parse pre-shared key"),
		},
		"valid settings": {
			settings: Settings{
				PrivateKey:   validKey1,
				PublicKey:    validKey2,
				PreSharedKey: validKey3,
				FirewallMark: 9876,
				Endpoint:     netip.AddrPortFrom(netip.AddrFrom4([4]byte{99, 99, 99, 99}), 51820),
			},
			config: wgtypes.Config{
				PrivateKey:   parseKey(t, validKey1),
				ReplacePeers: true,
				FirewallMark: intPtr(9876),
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:    *parseKey(t, validKey2),
						PresharedKey: parseKey(t, validKey3),
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IPv4(0, 0, 0, 0),
								Mask: []byte{0, 0, 0, 0},
							},
							{
								IP:   net.IPv6zero,
								Mask: []byte(net.IPv6zero),
							},
						},
						ReplaceAllowedIPs: true,
						Endpoint: &net.UDPAddr{
							IP:   net.IP{99, 99, 99, 99},
							Port: 51820,
						},
					},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config, err := makeDeviceConfig(testCase.settings)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.config, config)
		})
	}
}

func Test_allIPv4(t *testing.T) {
	t.Parallel()
	ipNet := allIPv4()
	assert.Equal(t, "0.0.0.0/0", ipNet.String())
}

func Test_allIPv6(t *testing.T) {
	t.Parallel()
	ipNet := allIPv6()
	assert.Equal(t, "::/0", ipNet.String())
}
