package settings

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_Wireguard_validate(t *testing.T) {
	t.Parallel()

	validKey := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

	testCases := map[string]struct {
		wireguard     Wireguard
		vpnProvider   string
		ipv6Supported bool
		amneziawg     bool
		err           error
	}{
		"valid PIA wireguard with empty private key and addresses": {
			wireguard: Wireguard{
				PrivateKey:                  ptrTo(""),
				PreSharedKey:                ptrTo(""),
				AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "auto",
			},
			vpnProvider: providers.PrivateInternetAccess,
		},
		"valid standard wireguard": {
			wireguard: Wireguard{
				PrivateKey:                  ptrTo(validKey),
				PreSharedKey:                ptrTo(""),
				Addresses:                   []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32)},
				AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "auto",
			},
			vpnProvider: providers.Mullvad,
		},
		"standard wireguard missing private key": {
			wireguard: Wireguard{
				PrivateKey:                  ptrTo(""),
				PreSharedKey:                ptrTo(""),
				Addresses:                   []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32)},
				AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "auto",
			},
			vpnProvider: providers.Mullvad,
			err:         errors.New("private key is not set"),
		},
		"standard wireguard missing addresses": {
			wireguard: Wireguard{
				PrivateKey:                  ptrTo(validKey),
				PreSharedKey:                ptrTo(""),
				AllowedIPs:                  []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)},
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "auto",
			},
			vpnProvider: providers.Mullvad,
			err:         errors.New("interface address is not set"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.wireguard.validate(testCase.vpnProvider,
				testCase.ipv6Supported, testCase.amneziawg)

			if testCase.err != nil {
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
