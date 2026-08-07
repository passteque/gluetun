package auth

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Read reads the toml file specified by the filepath given.
func Test_Read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		fileContent string
		settings    Settings
		errMessage  string
	}{
		"empty_file": {},
		"malformed_toml": {
			fileContent: "this is not a toml file",
			errMessage:  `toml decoding file: toml: expected character =`,
		},
		"unknown_field": {
			fileContent: `unknown = "what is this"`,
			errMessage: `toml decoding file: strict mode: fields in the document are missing in the target struct:
1| unknown = "what is this"
 | ~~~~~~~ unknown field`,
		},
		"filled_settings": {
			fileContent: `[[roles]]
name = "public"
auth = "none"
routes = ["GET /v1/vpn/status", "PUT /v1/vpn/status"]

[[roles]]
name = "client"
auth = "apikey"
apikey = "xyz"
routes = ["GET /v1/vpn/status"]
`,
			settings: Settings{
				Roles: []Role{{
					Name:   "public",
					Auth:   AuthNone,
					Routes: []string{"GET /v1/vpn/status", "PUT /v1/vpn/status"},
				}, {
					Name:   "client",
					Auth:   AuthAPIKey,
					APIKey: "xyz",
					Routes: []string{"GET /v1/vpn/status"},
				}},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			filepath := tempDir + "/config.toml"
			const permissions fs.FileMode = 0o600
			err := os.WriteFile(filepath, []byte(testCase.fileContent), permissions)
			require.NoError(t, err)

			settings, err := Read(filepath)

			assert.Equal(t, testCase.settings, settings)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
