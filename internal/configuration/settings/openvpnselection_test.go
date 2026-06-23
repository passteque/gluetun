package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_OpenVPNSelection_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  OpenVPNSelection
		provider   string
		errMessage string
	}{
		"purevpn_default_selection_valid": {
			selection: openVPNSelectionForValidation(providers.Purevpn),
			provider:  providers.Purevpn,
		},
		"purevpn_TCP_without_custom_port_valid": {
			selection: func() OpenVPNSelection {
				s := openVPNSelectionForValidation(providers.Purevpn)
				s.Protocol = constants.TCP
				return s
			}(),
			provider: providers.Purevpn,
		},
		"purevpn_custom_port_rejected": {
			selection: func() OpenVPNSelection {
				s := openVPNSelectionForValidation(providers.Purevpn)
				*s.CustomPort = 1194
				return s
			}(),
			provider:   providers.Purevpn,
			errMessage: "custom endpoint port is not allowed: for VPN service provider purevpn",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.selection.validate(testCase.provider)
			if testCase.errMessage == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errMessage)
			}
		})
	}
}

func openVPNSelectionForValidation(provider string) OpenVPNSelection {
	selection := OpenVPNSelection{}
	selection.setDefaults(provider)
	return selection
}
