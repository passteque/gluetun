package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Wireguard_read_allowedIPs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input      string
		allowedIPs []netip.Prefix
		errMessage string
	}{
		"allowed_ips_unset": {},
		"spaces": {
			input:      " 0.0.0.0/0 , ::/0 ",
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		},
		"invalid_prefix": {input: "10.0.0.0/33", errMessage: "parsing allowed IP"},
		"empty_element":  {input: "0.0.0.0/0,", errMessage: "parsing allowed IP"},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settingsReader := reader.New(reader.Settings{Sources: []reader.Source{
				mapSource{"WIREGUARD_ALLOWED_IPS": testCase.input},
			}})
			wireguard := Wireguard{}
			const amneziaWG = false
			err := wireguard.read(settingsReader, amneziaWG)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.allowedIPs, wireguard.AllowedIPs)
		})
	}
}
