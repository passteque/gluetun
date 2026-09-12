package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

type testFilterChoicesGetter struct {
	choices models.FilterChoices
}

func (f testFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return f.choices
}

type testWarner struct{}

func (testWarner) Warn(string) {}

func Test_VPN_validatePIAWireguard(t *testing.T) {
	t.Parallel()

	const username = "user"
	const password = "password"
	const region = "CA Vancouver"
	testCases := map[string]struct {
		username        string
		password        string
		regions         []string
		names           []string
		wireguardKey    string
		preSharedKey    string
		addresses       []netip.Prefix
		expectedErrPart string
	}{
		"valid": {
			username: username,
			password: password,
			regions:  []string{region},
		},
		"valid_region_id": {
			username: username,
			password: password,
			regions:  []string{"ca_vancouver"},
		},
		"valid_live_server_name": {
			username: username,
			password: password,
			names:    []string{"vancouver439"},
		},
		"username_missing": {
			password:        password,
			regions:         []string{region},
			expectedErrPart: "username is empty: set OPENVPN_USER",
		},
		"password_missing": {
			username:        username,
			regions:         []string{region},
			expectedErrPart: "password is empty: set OPENVPN_PASSWORD",
		},
		"server_selection_missing": {
			username:        username,
			password:        password,
			expectedErrPart: "server selection is empty",
		},
		"static_private_key_set": {
			username:        username,
			password:        password,
			regions:         []string{region},
			wireguardKey:    "not-used",
			expectedErrPart: "private key must not be set",
		},
		"static_pre_shared_key_set": {
			username:        username,
			password:        password,
			regions:         []string{region},
			preSharedKey:    "not-used",
			expectedErrPart: "pre-shared key must not be set",
		},
		"static_interface_address_set": {
			username:        username,
			password:        password,
			regions:         []string{region},
			addresses:       []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			expectedErrPart: "interface addresses must not be set",
		},
	}

	filterChoicesGetter := testFilterChoicesGetter{
		choices: models.FilterChoices{Regions: []string{region}},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			vpnSettings := VPN{
				Type: vpn.Wireguard,
				Provider: Provider{
					Name: providers.PrivateInternetAccess,
					ServerSelection: ServerSelection{
						VPN:     vpn.Wireguard,
						Regions: testCase.regions,
						Names:   testCase.names,
					},
				},
			}
			vpnSettings.setDefaults()
			*vpnSettings.OpenVPN.User = testCase.username
			*vpnSettings.OpenVPN.Password = testCase.password
			*vpnSettings.Wireguard.PrivateKey = testCase.wireguardKey
			*vpnSettings.Wireguard.PreSharedKey = testCase.preSharedKey

			vpnSettings.Wireguard.Addresses = testCase.addresses
			err := vpnSettings.Validate(filterChoicesGetter, false, testWarner{})

			if testCase.expectedErrPart == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.expectedErrPart)
			}
		})
	}
}
