package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopWarner struct{}

func (noopWarner) Warnf(string, ...interface{}) {}

func Test_Source_Get_amneziaWGConfigFields(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		key   string
		value string
	}{
		"allowed_ips": {
			key:   "amneziawg_allowed_ips",
			value: "0.0.0.0/0, ::/0",
		},
		"persistent_keepalive": {
			key:   "amneziawg_persistent_keepalive_interval",
			value: "25-35",
		},
		"dns": {
			key:   "amneziawg_dns",
			value: "1.1.1.1, 8.8.8.8",
		},
		"random_trailers": {
			key:   "amneziawg_random_trailers",
			value: "on",
		},
		"disable_cookies": {
			key:   "amneziawg_disable_cookies",
			value: "on",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootDirectory := t.TempDir()
			configDirectory := filepath.Join(rootDirectory, "amneziawg")
			err := os.Mkdir(configDirectory, fs.FileMode(0o700))
			require.NoError(t, err)
			config := `[Interface]
PrivateKey = qOZ8vN2mK4pL7wR1tY6uI3oP5aS9dF0gH8jK2lM4nB0=
DNS = 1.1.1.1, 8.8.8.8
RandomTrailers = on
DisableCookies = on

[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25-35
`
			configPath := filepath.Join(configDirectory, "awg0.conf")
			const permission = fs.FileMode(0o600)
			err = os.WriteFile(configPath, []byte(config), permission)
			require.NoError(t, err)
			source := &Source{
				rootDirectory: rootDirectory,
				environ:       map[string]string{},
				warner:        noopWarner{},
			}

			value, isSet := source.Get(testCase.key)

			assert.True(t, isSet)
			assert.Equal(t, testCase.value, value)
		})
	}
}

func Test_Source_Get_amneziaWGFallback(t *testing.T) {
	t.Parallel()

	const key = "amneziawg_persistent_keepalive_interval"
	const individualValue = "25s"
	testCases := map[string]struct {
		config     *string
		individual *string
		customPath bool
		value      string
		isSet      bool
	}{
		"no_config": {individual: new(individualValue), value: individualValue, isSet: true},
		"missing_config_field": {
			config: new("[Interface]\nJc = 4\n"), individual: new(individualValue), value: individualValue, isSet: true,
		},
		"custom_file_path": {individual: new(individualValue), customPath: true, value: individualValue, isSet: true},
		"config_takes_precedence": {
			config:     new("[Interface]\n[Peer]\nPersistentKeepalive = 25-35\n"),
			individual: new(individualValue), value: "25-35", isSet: true,
		},
		"zero_config_value_takes_precedence": {
			config:     new("[Interface]\n[Peer]\nPersistentKeepalive = 0\n"),
			individual: new(individualValue), value: "0", isSet: true,
		},
		"unset": {},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootDirectory := t.TempDir()
			source := &Source{rootDirectory: rootDirectory, environ: map[string]string{}, warner: noopWarner{}}
			if testCase.config != nil {
				configDirectory := filepath.Join(rootDirectory, "amneziawg")
				err := os.Mkdir(configDirectory, 0o700)
				require.NoError(t, err)
				err = os.WriteFile(filepath.Join(configDirectory, "awg0.conf"), []byte(*testCase.config), 0o600)
				require.NoError(t, err)
			}
			if testCase.individual != nil {
				path := filepath.Join(rootDirectory, key)
				if testCase.customPath {
					path = filepath.Join(rootDirectory, "custom_keepalive")
					source.environ["AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL_FILE"] = path
				}
				err := os.WriteFile(path, []byte(*testCase.individual), 0o600)
				require.NoError(t, err)
			}

			value, isSet := source.Get(key)

			assert.Equal(t, testCase.isSet, isSet)
			assert.Equal(t, testCase.value, value)
		})
	}
}
