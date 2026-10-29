package settings

import (
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_Wireguard_validate_privateKey(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnProvider string
		errMessage  string
	}{
		"nordvpn_access_token": {
			vpnProvider: providers.Nordvpn,
			errMessage: "private key is not valid: wgtypes: incorrect key size: 48 - " +
				"you might be using your access token instead of the Wireguard private key",
		},
		"mullvad_invalid_key": {
			vpnProvider: providers.Mullvad,
			errMessage:  "private key is not valid: wgtypes: incorrect key size: 48",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wireguard := Wireguard{
				PrivateKey: new(strings.Repeat("a", 64)), // 48 bytes once base64 decoded
			}
			wireguard.setDefaults(testCase.vpnProvider)

			err := wireguard.validate(testCase.vpnProvider, false, false)

			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
