package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Source_ParseAmneziawgConf(t *testing.T) {
	t.Parallel()

	t.Run("no_file", func(t *testing.T) {
		t.Parallel()

		noFile := filepath.Join(t.TempDir(), "doesnotexist")
		wireguard, err := ParseAmneziawgConf(noFile)
		assert.Equal(t, AmneziawgConfig{}, wireguard)
		assert.NoError(t, err)
	})

	testCases := map[string]struct {
		fileContent string
		amneziawg   AmneziawgConfig
		errMessage  string
	}{
		"ini_load_error": {
			fileContent: "invalid",
			errMessage:  "loading ini from reader: key-value delimiter not found: invalid",
		},
		"empty_file": {
			errMessage: `getting interface section: section "interface" does not exist`,
		},
		"success": {
			fileContent: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
DNS = 193.138.218.74, 1.1.1.1
Jc = 4
H1 = 721391205
I1 = <b 0x1234>
RandomTrailers = on
DisableCookies = on

[Peer]
PresharedKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25-35
`,
			amneziawg: AmneziawgConfig{
				Wireguard: WireguardConfig{
					PrivateKey:          ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
					PreSharedKey:        ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
					Addresses:           ptrTo("10.38.22.35/32"),
					DNS:                 ptrTo("193.138.218.74, 1.1.1.1"),
					AllowedIPs:          ptrTo("0.0.0.0/0, ::/0"),
					PersistentKeepalive: ptrTo("25-35"),
				},
				Jc:             ptrTo("4"),
				H1:             ptrTo("721391205"),
				I1:             ptrTo("<b 0x1234>"),
				RandomTrailers: ptrTo("on"),
				DisableCookies: ptrTo("on"),
			},
		},
		"v3_parameters": {
			fileContent: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
HeaderProtectionKey = qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0=
ContentPaddingAddition = 66-93
RekeyAfterTime = 110-126
RekeyTimeout = 5
RejectAfterTime = 170-182
KeepaliveTimeout = 12-17
MaxHandshakeAttempts = 16

[Peer]
PublicKey = QMNoEriYqOcgOfqNb5XmFThzMGXMOyEiIiCmkmS8VyQ=
`,
			amneziawg: AmneziawgConfig{
				Wireguard: WireguardConfig{
					PrivateKey: new("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
					Addresses:  new("10.38.22.35/32"),
					PublicKey:  new("QMNoEriYqOcgOfqNb5XmFThzMGXMOyEiIiCmkmS8VyQ="),
				},
				HeaderProtectionKey:    new("qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0="),
				ContentPaddingAddition: new("66-93"),
				RekeyAfterTime:         new("110-126"),
				RekeyTimeout:           new("5"),
				RejectAfterTime:        new("170-182"),
				KeepaliveTimeout:       new("12-17"),
				MaxHandshakeAttempts:   new("16"),
			},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			configFile := filepath.Join(t.TempDir(), "awg.conf")
			const permission = fs.FileMode(0o600)
			err := os.WriteFile(configFile, []byte(testCase.fileContent), permission)
			require.NoError(t, err)

			wireguard, err := ParseAmneziawgConf(configFile)

			assert.Equal(t, testCase.amneziawg, wireguard)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
