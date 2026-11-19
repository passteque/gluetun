package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_validateFeatureFilters(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider        string
		portForwardOnly bool
		errMessage      string
	}{
		"purevpn_port_forward_only": {
			provider:        providers.Purevpn,
			portForwardOnly: true,
		},
		"purevpn_no_port_forward_only": {
			provider: providers.Purevpn,
		},
		"private_internet_access_port_forward_only": {
			provider:        providers.PrivateInternetAccess,
			portForwardOnly: true,
		},
		"mullvad_port_forward_only": {
			provider:        providers.Mullvad,
			portForwardOnly: true,
			errMessage:      "port forwarding only filter is not supported",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := ServerSelection{}.WithDefaults(testCase.provider)
			settings.PortForwardOnly = ptrTo(testCase.portForwardOnly)

			err := validateFeatureFilters(settings, testCase.provider)
			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
		})
	}
}
