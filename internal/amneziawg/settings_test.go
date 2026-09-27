package amneziawg

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Settings_uapiConfig(t *testing.T) {
	t.Parallel()

	const defaults = "jc=0\njmin=0\njmax=0\ns1=0\ns2=0\ns3=0\ns4=0"

	testCases := map[string]struct {
		settings Settings
		config   string
	}{
		"defaults": {
			settings: Settings{},
			config:   defaults,
		},
		"junk_padding_signature": {
			settings: Settings{
				JunkPacketCount: 4,
				JunkPacketMin:   20,
				JunkPacketMax:   60,
				PaddingS1:       80,
				PaddingS2:       70,
				PaddingS3:       60,
				PaddingS4:       50,
				HeaderH1:        "1234-5678",
				InitPacketI1:    "<b 0x1234>",
			},
			config: "jc=4\njmin=20\njmax=60\n" +
				"s1=80\ns2=70\ns3=60\ns4=50\n" +
				"h1=1234-5678\n" +
				"i1=<b 0x1234>",
		},
		"v3_parameters": {
			settings: Settings{
				PaddingS1:              64,
				PaddingS2:              64,
				PaddingS3:              64,
				PaddingS4:              64,
				HeaderProtectionKey:    "qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0=",
				ContentPaddingAddition: [2]uint32{64, 128},
				RekeyAfterTime:         [2]uint32{110, 126},
				RekeyTimeout:           [2]uint32{5, 5},
				RejectAfterTime:        [2]uint32{170, 182},
				KeepaliveTimeout:       [2]uint32{12, 17},
				MaxHandshakeAttempts:   [2]uint32{3, 3},
			},
			config: "jc=0\njmin=0\njmax=0\n" +
				"s1=64\ns2=64\ns3=64\ns4=64\n" +
				"header_protection_key=a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d\n" +
				"content_padding_addition=64-128\n" +
				"rekey_after_time=110-126\n" +
				"rekey_timeout=5\n" +
				"reject_after_time=170-182\n" +
				"keepalive_timeout=12-17\n" +
				"max_handshake_attempts=3",
		},
		"base64_header_protection_key": {
			settings: Settings{
				HeaderProtectionKey: "qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0=",
			},
			config: defaults + "\n" +
				"header_protection_key=a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d",
		},
		"version_3_1_flags": {
			settings: Settings{
				RandomTrailers: true,
				DisableCookies: true,
			},
			config: defaults + "\nrandom_trailers=true\ndisable_cookies=true",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config, err := testCase.settings.uapiConfig()

			require.NoError(t, err)
			assert.Equal(t, testCase.config, config)
		})
	}
}

func Test_Settings_peerUAPIConfig(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Settings
		config   string
		errMsg   string
	}{
		"disabled": {},
		"range": {
			settings: Settings{
				Wireguard: wireguard.Settings{
					PublicKey: "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q=",
				},
				PersistentKeepaliveInterval: [2]uint32{25, 35},
			},
			config: "public_key=a0c3527ffcc9d29b75722cbea88464f119727ecf5a71cc2e44b9ca77ce589754\n" +
				"persistent_keepalive_interval=25-35",
		},
		"invalid_public_key": {
			settings: Settings{
				Wireguard:                   wireguard.Settings{PublicKey: "invalid"},
				PersistentKeepaliveInterval: [2]uint32{25, 35},
			},
			errMsg: "parsing public key",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config, err := testCase.settings.peerUAPIConfig()

			if testCase.errMsg != "" {
				assert.ErrorContains(t, err, testCase.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.config, config)
		})
	}
}

func Test_headerProtectionKeyToHex(t *testing.T) {
	t.Parallel()

	keyBytes := []byte{
		0xa8, 0xe6, 0x7c, 0xbc, 0xdd, 0xa6, 0x2b, 0x8a,
		0x4b, 0xef, 0x04, 0x75, 0xb5, 0x8e, 0xae, 0x23,
		0x7a, 0x0f, 0xe5, 0xa4, 0xbd, 0x74, 0x5d, 0x20,
		0x1f, 0xc8, 0xca, 0xda, 0x53, 0x38, 0x9c, 0x1d,
	}
	const hexadecimalKey = "a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d"

	testCases := map[string]struct {
		key            string
		hexadecimalKey string
		errMessage     string
	}{
		"empty": {},
		"base64": {
			key:            base64.StdEncoding.EncodeToString(keyBytes),
			hexadecimalKey: hexadecimalKey,
		},
		"invalid_encoding": {
			key:        "not-a-key!",
			errMessage: "must be a 32-byte base64 encoded key",
		},
		"hexadecimal": {
			key:        hexadecimalKey,
			errMessage: "must be a 32-byte base64 encoded key: wgtypes: incorrect key size: 48",
		},
		"invalid_base64_size": {
			key:        base64.StdEncoding.EncodeToString([]byte("too short")),
			errMessage: "must be a 32-byte base64 encoded key: wgtypes: incorrect key size: 9",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hexadecimalKey, err := headerProtectionKeyToHex(testCase.key)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.hexadecimalKey, hexadecimalKey)
		})
	}
}

func Test_Settings_Check(t *testing.T) {
	t.Parallel()

	const (
		wireguardKey        = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
		protectionBase64Key = "qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0="
	)

	validWireguardSettings := func() wireguard.Settings {
		settings := wireguard.Settings{}
		settings.SetDefaults()
		settings.InterfaceName = "wg0"
		settings.PrivateKey = wireguardKey
		settings.PublicKey = wireguardKey
		settings.Endpoint = netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51820)
		settings.Addresses = []netip.Prefix{
			netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
		}
		settings.FirewallMark = 100

		return settings
	}

	testCases := map[string]struct {
		settings Settings
		errMsg   string
	}{
		"defaults": {
			settings: Settings{Wireguard: validWireguardSettings()},
		},
		"header_protection_with_small_padding": {
			settings: Settings{
				Wireguard:           validWireguardSettings(),
				HeaderProtectionKey: protectionBase64Key,
				PaddingS1:           64,
				PaddingS2:           64,
				PaddingS3:           11,
				PaddingS4:           64,
			},
			errMsg: "header protection requires padding s3 to be at least 12: got 11",
		},
		"header_protection_with_enough_padding": {
			settings: Settings{
				Wireguard:           validWireguardSettings(),
				HeaderProtectionKey: protectionBase64Key,
				PaddingS1:           12,
				PaddingS2:           64,
				PaddingS3:           64,
				PaddingS4:           64,
			},
		},
		"invalid_header_protection_key": {
			settings: Settings{
				Wireguard:           validWireguardSettings(),
				HeaderProtectionKey: "not-a-key!",
			},
			errMsg: "invalid header protection key: must be a 32-byte base64 encoded key",
		},
		"small_padding_without_header_protection": {
			settings: Settings{
				Wireguard: validWireguardSettings(),
				PaddingS1: 1,
				PaddingS2: 2,
				PaddingS3: 3,
				PaddingS4: 4,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.Check()

			if testCase.errMsg != "" {
				assert.ErrorContains(t, err, testCase.errMsg)
				return
			}

			assert.NoError(t, err)
		})
	}
}
