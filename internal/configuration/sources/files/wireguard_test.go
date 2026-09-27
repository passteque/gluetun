package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

func ptrTo[T any](value T) *T { return &value }

func Test_Source_ParseWireguardConf(t *testing.T) {
	t.Parallel()

	t.Run("fail reading from file", func(t *testing.T) {
		t.Parallel()

		dirPath := t.TempDir()
		wireguard, err := ParseWireguardConf(dirPath)
		assert.Equal(t, WireguardConfig{}, wireguard)
		assert.Error(t, err)
		assert.Regexp(t, `loading ini from reader: BOM: read .+: is a directory`, err.Error())
	})

	t.Run("no file", func(t *testing.T) {
		t.Parallel()

		noFile := filepath.Join(t.TempDir(), "doesnotexist")
		wireguard, err := ParseWireguardConf(noFile)
		assert.Equal(t, WireguardConfig{}, wireguard)
		assert.NoError(t, err)
	})

	testCases := map[string]struct {
		fileContent string
		wireguard   WireguardConfig
		errMessage  string
	}{
		"ini load error": {
			fileContent: "invalid",
			errMessage:  "loading ini from reader: key-value delimiter not found: invalid",
		},
		"empty file": {},
		"interface_section_missing": {
			fileContent: `
[Peer]
PresharedKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
`,
			wireguard: WireguardConfig{
				PreSharedKey: ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
			},
		},
		"success": {
			fileContent: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
DNS = 193.138.218.74, 1.1.1.1

[Peer]
PresharedKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`,
			wireguard: WireguardConfig{
				PrivateKey:          ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
				PreSharedKey:        ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
				Addresses:           ptrTo("10.38.22.35/32"),
				DNS:                 ptrTo("193.138.218.74, 1.1.1.1"),
				AllowedIPs:          ptrTo("0.0.0.0/0, ::/0"),
				PersistentKeepalive: ptrTo("25"),
			},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			configFile := filepath.Join(t.TempDir(), "wg.conf")
			const permission = fs.FileMode(0o600)
			err := os.WriteFile(configFile, []byte(testCase.fileContent), permission)
			require.NoError(t, err)

			wireguard, err := ParseWireguardConf(configFile)

			assert.Equal(t, testCase.wireguard, wireguard)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_parseWireguardInterfaceSection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		iniData    string
		privateKey *string
		addresses  *string
		dns        *string
	}{
		"no_fields": {
			iniData: `[Interface]`,
		},
		"only_private_key": {
			iniData: `[Interface]
PrivateKey = x
`,
			privateKey: ptrTo("x"),
		},
		"all_fields": {
			iniData: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
DNS = 1.1.1.1, 2606:4700:4700::1111
`,
			privateKey: ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
			addresses:  ptrTo("10.38.22.35/32"),
			dns:        ptrTo("1.1.1.1, 2606:4700:4700::1111"),
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			iniFile, err := ini.Load([]byte(testCase.iniData))
			require.NoError(t, err)
			iniSection, err := iniFile.GetSection("Interface")
			require.NoError(t, err)

			config := WireguardConfig{}
			parseWireguardInterfaceSection(iniSection, &config)

			assert.Equal(t, testCase.privateKey, config.PrivateKey)
			assert.Equal(t, testCase.addresses, config.Addresses)
			assert.Equal(t, testCase.dns, config.DNS)
		})
	}
}

func Test_parseWireguardPeerSection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		iniData      string
		preSharedKey *string
		publicKey    *string
		endpointIP   *string
		endpointPort *string
		allowedIPs   *string
		keepalive    *string
	}{
		"public key set": {
			iniData: `[Peer]
PublicKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=`,
			publicKey: ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
		},
		"endpoint_only_host": {
			iniData: `[Peer]
Endpoint = x`,
			endpointIP: ptrTo("x"),
		},
		"endpoint_no_port": {
			iniData: `[Peer]
Endpoint = x:`,
			endpointIP:   ptrTo("x"),
			endpointPort: ptrTo(""),
		},
		"valid_endpoint": {
			iniData: `[Peer]
Endpoint = 1.2.3.4:51820`,
			endpointIP:   ptrTo("1.2.3.4"),
			endpointPort: ptrTo("51820"),
		},
		"all_set": {
			iniData: `[Peer]
PublicKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25-35`,
			publicKey:    ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
			endpointIP:   ptrTo("1.2.3.4"),
			endpointPort: ptrTo("51820"),
			allowedIPs:   ptrTo("0.0.0.0/0, ::/0"),
			keepalive:    ptrTo("25-35"),
		},
		"ipv6_endpoint": {
			iniData: `[Peer]
Endpoint = [2a02:bbbb:aaaa:8075::10]:51820`,
			endpointIP:   ptrTo("2a02:bbbb:aaaa:8075::10"),
			endpointPort: ptrTo("51820"),
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			iniFile, err := ini.Load([]byte(testCase.iniData))
			require.NoError(t, err)
			iniSection, err := iniFile.GetSection("Peer")
			require.NoError(t, err)

			config := WireguardConfig{}
			parseWireguardPeerSection(iniSection, &config)

			assert.Equal(t, testCase.preSharedKey, config.PreSharedKey)
			assert.Equal(t, testCase.publicKey, config.PublicKey)
			assert.Equal(t, testCase.endpointIP, config.EndpointIP)
			assert.Equal(t, testCase.endpointPort, config.EndpointPort)
			assert.Equal(t, testCase.allowedIPs, config.AllowedIPs)
			assert.Equal(t, testCase.keepalive, config.PersistentKeepalive)
		})
	}
}
