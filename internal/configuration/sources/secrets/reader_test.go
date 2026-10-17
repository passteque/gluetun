package secrets

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Source_Get(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		makeSource func(tempDir string) (source *Source, err error)
		key        string
		value      string
		isSet      bool
	}{
		"empty_key": {
			makeSource: func(tempDir string) (source *Source, err error) {
				return &Source{
					rootDirectory: tempDir,
					environ:       map[string]string{},
				}, nil
			},
		},
		"no_secret_file": {
			makeSource: func(tempDir string) (source *Source, err error) {
				return &Source{
					rootDirectory: tempDir,
					environ:       map[string]string{},
				}, nil
			},
			key: "test_file",
		},
		"empty_secret_file": {
			makeSource: func(tempDir string) (source *Source, err error) {
				secretFilepath := filepath.Join(tempDir, "test_file")
				const permission = fs.FileMode(0o600)
				err = os.WriteFile(secretFilepath, nil, permission)
				if err != nil {
					return nil, err
				}
				return &Source{
					rootDirectory: tempDir,
					environ:       map[string]string{},
				}, nil
			},
			key:   "test_file",
			isSet: true,
		},
		"default_secret_file": {
			makeSource: func(tempDir string) (source *Source, err error) {
				secretFilepath := filepath.Join(tempDir, "test_file")
				const permission = fs.FileMode(0o600)
				err = os.WriteFile(secretFilepath, []byte{'A'}, permission)
				if err != nil {
					return nil, err
				}
				return &Source{
					rootDirectory: tempDir,
					environ:       map[string]string{},
				}, nil
			},
			key:   "test_file",
			value: "A",
			isSet: true,
		},
		"env_specified_secret_file": {
			makeSource: func(tempDir string) (source *Source, err error) {
				secretFilepath := filepath.Join(tempDir, "test_file_custom")
				const permission = fs.FileMode(0o600)
				err = os.WriteFile(secretFilepath, []byte{'A'}, permission)
				if err != nil {
					return nil, err
				}
				return &Source{
					rootDirectory: tempDir,
					environ: map[string]string{
						"TEST_FILE_SECRETFILE": secretFilepath,
					},
				}, nil
			},
			key:   "test_file",
			value: "A",
			isSet: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			source, err := testCase.makeSource(t.TempDir())
			require.NoError(t, err)

			value, isSet := source.Get(testCase.key)
			assert.Equal(t, testCase.value, value)
			assert.Equal(t, testCase.isSet, isSet)
		})
	}
}

type noopWarner struct{}

func (noopWarner) Warnf(string, ...any) {}

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
					source.environ["AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL_SECRETFILE"] = path
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
