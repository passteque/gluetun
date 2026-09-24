package amneziawg

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_Settings_uapiConfig(t *testing.T) {
	t.Parallel()

	const keyString = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
	const shortRange = "5-10"
	settings := Settings{
		Wireguard:                   wireguard.Settings{PublicKey: keyString},
		HeaderProtectionKey:         keyString,
		ContentPaddingAddition:      "16-32",
		RekeyAfterTime:              "120-180",
		RekeyTimeout:                shortRange,
		RejectAfterTime:             "180-240",
		KeepaliveTimeout:            "10-20",
		MaxHandshakeAttempts:        shortRange,
		PersistentKeepaliveInterval: "25s",
		RandomTrailers:              true,
		DisableCookies:              true,
	}

	config, err := settings.uapiConfig()
	require.NoError(t, err)
	key, err := wgtypes.ParseKey(keyString)
	require.NoError(t, err)
	hexKey := hex.EncodeToString(key[:])
	config = "\n" + config + "\n"
	for _, line := range []string{
		"header_protection_key=" + hexKey,
		"content_padding_addition=16-32",
		"rekey_after_time=120-180",
		"rekey_timeout=" + shortRange,
		"reject_after_time=180-240",
		"keepalive_timeout=10-20",
		"max_handshake_attempts=" + shortRange,
		"random_trailers=true",
		"disable_cookies=true",
		"public_key=" + hexKey,
		"persistent_keepalive_interval=25",
	} {
		assert.Contains(t, config, "\n"+line+"\n")
	}
}

func Test_Settings_CheckAmneziaWG3(t *testing.T) {
	t.Parallel()

	const keyString = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="
	baseSettings := Settings{
		Wireguard: wireguard.Settings{
			PrivateKey:   keyString,
			PublicKey:    keyString,
			Endpoint:     netip.MustParseAddrPort("1.2.3.4:51820"),
			Addresses:    []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			FirewallMark: 51820,
		},
		HeaderProtectionKey:         keyString,
		PaddingS1:                   12,
		PaddingS2:                   12,
		PaddingS3:                   12,
		PaddingS4:                   12,
		ContentPaddingAddition:      "16-32",
		RekeyAfterTime:              "120-180",
		RekeyTimeout:                "5-10",
		RejectAfterTime:             "180-240",
		KeepaliveTimeout:            "10-20",
		MaxHandshakeAttempts:        "5-10",
		PersistentKeepaliveInterval: "22-30",
	}
	baseSettings.SetDefaults()

	testCases := map[string]struct {
		modify       func(settings *Settings)
		errorMessage string
	}{
		"valid": {},
		"invalid_header_protection_key": {
			modify:       func(settings *Settings) { settings.HeaderProtectionKey = "invalid" },
			errorMessage: "parsing header protection key",
		},
		"header_padding_too_small": {
			modify:       func(settings *Settings) { settings.PaddingS4 = 11 },
			errorMessage: "S1-S4 must all be at least 12",
		},
		"invalid_range": {
			modify:       func(settings *Settings) { settings.RekeyTimeout = "10-5" },
			errorMessage: "parsing rekey timeout",
		},
		"invalid_persistent_keepalive": {
			modify:       func(settings *Settings) { settings.PersistentKeepaliveInterval = "sometimes" },
			errorMessage: "parsing persistent keepalive interval",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			settings := baseSettings
			if testCase.modify != nil {
				testCase.modify(&settings)
			}

			err := settings.Check()
			if testCase.errorMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.errorMessage)
			}
		})
	}
}
