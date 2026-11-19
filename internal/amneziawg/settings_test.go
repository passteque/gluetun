package amneziawg

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
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
				HeaderProtectionKey:    "a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d",
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
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := testCase.settings.uapiConfig()

			assert.Equal(t, testCase.config, config)
		})
	}
}

func Test_Settings_Check(t *testing.T) {
	t.Parallel()

	const (
		wireguardKey     = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
		protectionHexKey = "a8e67cbcdda62b8a4bef0475b58eae237a0fe5a4bd745d201fc8cada53389c1d"
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
				HeaderProtectionKey: protectionHexKey,
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
				HeaderProtectionKey: protectionHexKey,
				PaddingS1:           12,
				PaddingS2:           64,
				PaddingS3:           64,
				PaddingS4:           64,
			},
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
