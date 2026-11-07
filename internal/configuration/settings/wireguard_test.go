package settings

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_Wireguard_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings      Wireguard
		vpnProvider   string
		ipv6Supported bool
		errMessage    string
	}{
		"valid_settings": {
			settings: Wireguard{
				PrivateKey:                  ptrTo(strings.Repeat("A", 43) + "="), // 32 bytes once base64 decoded
				PreSharedKey:                ptrTo(""),
				Addresses:                   []netip.Prefix{netip.MustParsePrefix("10.5.0.2/32")},
				AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "auto",
			},
			vpnProvider: providers.Nordvpn,
		},
		"private_key_not_set": {
			settings: Wireguard{
				PrivateKey: ptrTo(""),
			},
			vpnProvider: providers.Nordvpn,
			errMessage:  "private key is not set",
		},
		"private_key_access_token_nordvpn": {
			settings: Wireguard{
				PrivateKey: ptrTo(strings.Repeat("a", 64)), // 48 bytes once base64 decoded
			},
			vpnProvider: providers.Nordvpn,
			errMessage: "private key is not valid: wgtypes: incorrect key size: 48 - " +
				"you might be using your access token instead of the Wireguard private key",
		},
		"private_key_access_token_mullvad": {
			settings: Wireguard{
				PrivateKey: ptrTo(strings.Repeat("a", 64)), // 48 bytes once base64 decoded
			},
			vpnProvider: providers.Mullvad,
			errMessage:  "private key is not valid: wgtypes: incorrect key size: 48",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.validate(testCase.vpnProvider, testCase.ipv6Supported)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
