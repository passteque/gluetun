package settings

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
)

func Test_PublicIP_read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		makeReader func(ctrl *gomock.Controller) *reader.Reader
		makeWarner func(ctrl *gomock.Controller) Warner
		settings   PublicIP
		errMessage string
	}{
		"nothing_read": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
		},
		"single_api_no_token": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API", value: "ipinfo"},
					{key: "PUBLICIP_API_TOKEN"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			settings: PublicIP{
				APIs: []PublicIPAPI{
					{Name: "ipinfo"},
				},
			},
		},
		"single_api_with_token": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API", value: "ipinfo"},
					{key: "PUBLICIP_API_TOKEN", value: "xyz"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			settings: PublicIP{
				APIs: []PublicIPAPI{
					{Name: "ipinfo", Token: "xyz"},
				},
			},
		},
		"multiple_apis_no_token": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API", value: "ipinfo,ip2location"},
					{key: "PUBLICIP_API_TOKEN"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			settings: PublicIP{
				APIs: []PublicIPAPI{
					{Name: "ipinfo"},
					{Name: "ip2location"},
				},
			},
		},
		"multiple_apis_with_token": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API", value: "ipinfo,ip2location"},
					{key: "PUBLICIP_API_TOKEN", value: "xyz,abc"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			settings: PublicIP{
				APIs: []PublicIPAPI{
					{Name: "ipinfo", Token: "xyz"},
					{Name: "ip2location", Token: "abc"},
				},
			},
		},
		"multiple_apis_with_and_without_token": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "PUBLICIP_PERIOD"},
					{key: "PUBLICIP_ENABLED"},
					{key: "IP_STATUS_FILE"},
					{key: "PUBLICIP_FILE"},
					{key: "PUBLICIP_API", value: "ipinfo,ip2location"},
					{key: "PUBLICIP_API_TOKEN", value: "xyz"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			settings: PublicIP{
				APIs: []PublicIPAPI{
					{Name: "ipinfo", Token: "xyz"},
					{Name: "ip2location"},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			reader := testCase.makeReader(ctrl)
			var warner Warner
			if testCase.makeWarner != nil {
				warner = testCase.makeWarner(ctrl)
			}

			var settings PublicIP
			err := settings.read(reader, warner)

			assert.Equal(t, testCase.settings, settings)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
