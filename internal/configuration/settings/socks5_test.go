package settings

import (
	"testing"

	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_Socks5_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		allowedCIDRs []string
		errMessage   string
	}{
		"no_allowed_cidrs": {},
		"valid_allowed_cidrs": {
			allowedCIDRs: []string{"192.168.1.2/32", "10.0.0.0/8", "2001:db8::1/128"},
		},
		"bare_ip_without_prefix": {
			allowedCIDRs: []string{"192.168.1.2"},
			errMessage:   `parsing allowed CIDR "192.168.1.2"`,
		},
		"invalid_cidr": {
			allowedCIDRs: []string{"not-a-cidr"},
			errMessage:   `parsing allowed CIDR "not-a-cidr"`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := Socks5{
				Enabled:          new(false),
				ListeningAddress: ":1080",
				Username:         new(""),
				Password:         new(""),
				AllowedCIDRs:     testCase.allowedCIDRs,
			}
			err := s.validate()

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Socks5_read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		makeReader func(ctrl *gomock.Controller) *reader.Reader
		s          Socks5
	}{
		"no_allowed_cidrs": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
		},
		"single_ips_and_networks": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS", value: "192.168.1.2/32,10.0.0.0/8"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			s: Socks5{
				AllowedCIDRs: []string{"192.168.1.2/32", "10.0.0.0/8"},
			},
		},
		"ipv6_single_ips_and_networks": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS", value: "2001:db8::1/128,2001:db8::/32"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			s: Socks5{
				AllowedCIDRs: []string{"2001:db8::1/128", "2001:db8::/32"},
			},
		},
		"empty_entries_stored_as_is": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS", value: "192.168.1.2/32,,10.0.0.0/8"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			s: Socks5{
				AllowedCIDRs: []string{"192.168.1.2/32", "", "10.0.0.0/8"},
			},
		},
		"spaces_not_trimmed": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS", value: "192.168.1.2/32, 10.0.0.0/8"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			s: Socks5{
				AllowedCIDRs: []string{"192.168.1.2/32", " 10.0.0.0/8"},
			},
		},
		"invalid_value_stored_as_is": {
			makeReader: func(ctrl *gomock.Controller) *reader.Reader {
				source := newMockSource(ctrl, []sourceKeyValue{
					{key: "SOCKS5_ENABLED"},
					{key: "SOCKS5_LISTENING_ADDRESS"},
					{key: "SOCKS5_USER"},
					{key: "SOCKS5_PASSWORD"},
					{key: "SOCKS5_ALLOWED_CIDRS", value: "not-a-cidr"},
				})
				return reader.New(reader.Settings{
					Sources: []reader.Source{source},
				})
			},
			s: Socks5{
				AllowedCIDRs: []string{"not-a-cidr"},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			r := testCase.makeReader(ctrl)

			var s Socks5
			err := s.read(r)

			assert.NoError(t, err)
			assert.Equal(t, testCase.s, s)
		})
	}
}

func Test_Socks5_String(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		s      Socks5
		expect string
	}{
		"enabled_with_allowed_cidrs": {
			s: Socks5{
				Enabled:          new(true),
				ListeningAddress: ":1080",
				Username:         new(""),
				Password:         new(""),
				AllowedCIDRs:     []string{"192.168.1.2/32", "10.0.0.0/8"},
			},
			expect: `SOCKS5 proxy server settings:
├── Enabled: yes
├── Listening address: :1080
└── Allowed IP ranges:
    ├── 192.168.1.2/32
    └── 10.0.0.0/8`,
		},
		"enabled_without_allowed_cidrs": {
			s: Socks5{
				Enabled:          new(true),
				ListeningAddress: ":1080",
				Username:         new(""),
				Password:         new(""),
			},
			expect: `SOCKS5 proxy server settings:
├── Enabled: yes
└── Listening address: :1080`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := testCase.s.String()

			assert.Equal(t, testCase.expect, result)
		})
	}
}
