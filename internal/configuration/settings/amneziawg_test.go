package settings

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AmneziaWg_validate(t *testing.T) {
	t.Parallel()

	privateKeyBytes := generate32Bytes()
	hexKey := hex.EncodeToString(privateKeyBytes)

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
		"header_protection_key_not_hexadecimal": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new("qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0=")
				return settings
			},
			errMessage: "header protection key:",
		},
		"header_protection_key_invalid_size": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new("abcd")
				return settings
			},
			errMessage: "header protection key: must be 32 bytes long, got 2",
		},
		"header_protection_key_valid": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new(hexKey)
				return settings
			},
		},
		"valid_v3_parameters": {
			makeSettings: func() AmneziaWg {
				settings := newSettings()
				settings.HeaderProtectionKey = new(hexKey)
				settings.ContentPaddingAddition = new([2]uint32{64, 128})
				settings.RekeyAfterTime = new([2]uint32{110, 126})
				settings.RekeyTimeout = new([2]uint32{5, 5})
				settings.RejectAfterTime = new([2]uint32{170, 182})
				settings.KeepaliveTimeout = new([2]uint32{12, 17})
				settings.MaxHandshakeAttempts = new([2]uint32{3, 3})
				return settings
			},
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
