package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseProvider(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		s          string
		provider   Provider
		errMessage string
	}{
		"empty": {
			errMessage: `API name is not valid: "" can only be ` +
				`"cloudflare", "ifconfigco", "ip2location", "ipinfo" or a custom echoip# url`,
		},
		"invalid": {
			s: "xyz",
			errMessage: `API name is not valid: "xyz" can only be ` +
				`"cloudflare", "ifconfigco", "ip2location", "ipinfo" or a custom echoip# url`,
		},
		"ipinfo": {
			s:        "ipinfo",
			provider: IPInfo,
		},
		"IpInfo": {
			s:        "IpInfo",
			provider: IPInfo,
		},
		"echoip_url_empty": {
			s: "echoip#",
			errMessage: `echoip# custom URL is not valid: "" ` +
				`does not match regular expression: ^http(s|):\/\/.+$`,
		},
		"echoip_url_invalid": {
			s: "echoip#postgres://localhost:3451",
			errMessage: `echoip# custom URL is not valid: "postgres://localhost:3451" ` +
				`does not match regular expression: ^http(s|):\/\/.+$`,
		},
		"echoip_url_valid": {
			s:        "echoip#http://localhost:3451",
			provider: Provider("echoip#http://localhost:3451"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, err := ParseProvider(testCase.s)

			assert.Equal(t, testCase.provider, provider)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
