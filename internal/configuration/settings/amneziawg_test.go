package settings

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AmneziaWg_validate(t *testing.T) {
	t.Parallel()

	privateKeyBytes := generate32Bytes()
	base64Key := base64.StdEncoding.EncodeToString(privateKeyBytes)

	newSettings := func() AmneziaWg {
		settings := AmneziaWg{}
		settings.setDefaults("custom")
		settings.Wireguard.PrivateKey = new(base64.StdEncoding.EncodeToString(privateKeyBytes))
		settings.Wireguard.Addresses = []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 2}), 32),
		}
		return settings
	}

	testCases := map[string]struct {
		makeSettings func() AmneziaWg
		errMessage   string
	}{
		"valid_defaults": {
			makeSettings: newSettings,
		},
		"header_protection_key_invalid_encoding": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new("not-a-key!")
				return settings
			},
			errMessage: "header protection key: must be a 32-byte base64 encoded key",
		},
		"header_protection_key_invalid_size": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new("abcd")
				return settings
			},
			errMessage: "header protection key: must be a 32-byte base64 encoded key: wgtypes: incorrect key size: 3",
		},
		"header_protection_key_hexadecimal": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new("a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d")
				return settings
			},
			errMessage: "header protection key: must be a 32-byte base64 encoded key: wgtypes: incorrect key size: 48",
		},
		"header_protection_key_valid_base64": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new(base64Key)
				return settings
			},
		},
		"valid_v3_parameters": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new(base64Key)
				settings.ContentPaddingAddition = new([2]uint32{64, 128})
				settings.RekeyAfterTime = new([2]uint32{110, 126})
				settings.RekeyTimeout = new([2]uint32{5, 5})
				settings.RejectAfterTime = new([2]uint32{170, 182})
				settings.KeepaliveTimeout = new([2]uint32{12, 17})
				settings.MaxHandshakeAttempts = new([2]uint32{3, 3})
				return settings
			},
		},
		"persistent_keepalive_invalid_range": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.PersistentKeepaliveInterval = new([2]uint32{35, 25})
				return settings
			},
			errMessage: "persistent keepalive maximum 25 must be greater than or equal to minimum 35",
		},
		"legacy_persistent_keepalive_fractional_second": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.Wireguard.PersistentKeepaliveInterval = new(1500 * time.Millisecond)
				return settings
			},
			errMessage: "legacy persistent keepalive interval: duration 1.5s must be a whole number of seconds",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := testCase.makeSettings()

			err := settings.validate("custom", true)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func Test_parseUint32Range(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		value      *string
		rangeValue *[2]uint32
		errMessage string
	}{
		"nil": {
			value: nil,
		},
		"single_number": {
			value:      new("42"),
			rangeValue: new([2]uint32{42, 42}),
		},
		"range": {
			value:      new("10-30"),
			rangeValue: new([2]uint32{10, 30}),
		},
		"max_uint32": {
			value:      new("4294967295"),
			rangeValue: new([2]uint32{4294967295, 4294967295}),
		},
		"zero": {
			value:      new("0"),
			rangeValue: new([2]uint32{0, 0}),
		},
		"minimum_too_large": {
			value:      new("4294967296"),
			errMessage: `minimum "4294967296" is not a valid 32 bits unsigned integer`,
		},
		"minimum_not_a_number": {
			value:      new("abc"),
			errMessage: `minimum "abc" is not a valid 32 bits unsigned integer`,
		},
		"maximum_not_a_number": {
			value:      new("10-abcd"),
			errMessage: `maximum "abcd" is not a valid 32 bits unsigned integer`,
		},
		"maximum_lower_than_minimum": {
			value:      new("30-10"),
			errMessage: "maximum 10 must be greater than or equal to minimum 30",
		},
		"too_many_fields": {
			value:      new("10-20-30"),
			errMessage: `"10-20-30" must be a number or a min-max pair of numbers`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rangeValue, err := parseUint32Range(testCase.value)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.rangeValue, rangeValue)
		})
	}
}

func Test_parsePersistentKeepaliveRange(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		value      *string
		rangeValue *[2]uint32
		errMessage string
	}{
		"nil": {},
		"seconds_duration": {
			value:      new("25s"),
			rangeValue: new([2]uint32{25, 25}),
		},
		"single_number": {
			value:      new("25"),
			rangeValue: new([2]uint32{25, 25}),
		},
		"range": {
			value:      new("25-35"),
			rangeValue: new([2]uint32{25, 35}),
		},
		"fractional_second": {
			value:      new("1500ms"),
			errMessage: "must be a whole number of seconds",
		},
		"negative": {
			value:      new("-1s"),
			errMessage: "duration -1s is negative",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rangeValue, err := parsePersistentKeepaliveRange(testCase.value)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.rangeValue, rangeValue)
		})
	}
}

func Test_AmneziaWg_overrideWith_persistentKeepalive(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		json          string
		expectedRange [2]uint32
	}{
		"legacy_duration": {
			json:          `{"wireguard":{"persistent_keep_alive_interval":25000000000}}`,
			expectedRange: [2]uint32{25, 25},
		},
		"keepalive_range": {
			json:          `{"persistent_keep_alive_interval":[25,35]}`,
			expectedRange: [2]uint32{25, 35},
		},
		"range_takes_precedence": {
			json: `{"wireguard":{"persistent_keep_alive_interval":10000000000},` +
				`"persistent_keep_alive_interval":[25,35]}`,
			expectedRange: [2]uint32{25, 35},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			other := AmneziaWg{}
			err := json.Unmarshal([]byte(testCase.json), &other)
			require.NoError(t, err)
			amneziaWg := AmneziaWg{
				Wireguard:                   Wireguard{PersistentKeepaliveInterval: new(time.Duration(0))},
				PersistentKeepaliveInterval: new([2]uint32{}),
			}
			amneziaWg.overrideWith(other)

			assert.Equal(t, testCase.expectedRange, *amneziaWg.PersistentKeepaliveInterval)
			assert.Zero(t, *amneziaWg.Wireguard.PersistentKeepaliveInterval)
		})
	}
}

func Test_AmneziaWg_setDefaults_legacyPersistentKeepalive(t *testing.T) {
	t.Parallel()

	amneziaWg := AmneziaWg{
		Wireguard: Wireguard{PersistentKeepaliveInterval: new(25 * time.Second)},
	}
	amneziaWg.setDefaults("custom")

	assert.Equal(t, [2]uint32{25, 25}, *amneziaWg.PersistentKeepaliveInterval)
	assert.Zero(t, *amneziaWg.Wireguard.PersistentKeepaliveInterval)
}

func Test_parseAmneziaWGDNSServers(t *testing.T) {
	t.Parallel()

	const addresses = "1.1.1.1, 2606:4700:4700::1111"
	const parseAddressError = "parsing address"
	testCases := map[string]struct {
		value      *string
		servers    []netip.AddrPort
		errMessage string
	}{
		"unset": {},
		"addresses": {
			value: new(addresses),
			servers: []netip.AddrPort{
				netip.MustParseAddrPort("1.1.1.1:53"), netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
			},
		},
		"search_domain_rejected": {value: new("example.internal"), errMessage: parseAddressError},
		"invalid_ipv4":           {value: new("999.1.1.1"), errMessage: parseAddressError},
		"invalid_ipv6":           {value: new("2001:db8:::1"), errMessage: parseAddressError},
		"empty_entry":            {value: new("1.1.1.1,"), errMessage: parseAddressError},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			servers, err := parseAmneziaWGDNSServers(testCase.value)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.servers, servers)
		})
	}
}

func Test_readAmneziaWGBool(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input      string
		value      *bool
		errMessage string
	}{
		"unset":         {},
		"zero":          {input: "0", value: new(false)},
		"one":           {input: "1", value: new(true)},
		"on":            {input: "on", value: new(true)},
		"off":           {input: "off", value: new(false)},
		"true":          {input: "true", value: new(true)},
		"false":         {input: "false", value: new(false)},
		"invalid_value": {input: "not_a_boolean", errMessage: "AMNEZIAWG_RANDOM_TRAILERS"},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const key = "AMNEZIAWG_RANDOM_TRAILERS"
			settingsReader := reader.New(reader.Settings{Sources: []reader.Source{mapSource{key: testCase.input}}})
			value, err := readAmneziaWGBool(settingsReader, key)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.value, value)
		})
	}
}
