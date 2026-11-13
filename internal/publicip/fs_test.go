package publicip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_persistPublicIP(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		existingContent string
		content         string
		expectedContent string
	}{
		"persist_ip_address": {
			content:         "1.2.3.4",
			expectedContent: "1.2.3.4",
		},
		"replace_ip_address": {
			existingContent: "1.2.3.4",
			content:         "::1",
			expectedContent: "::1",
		},
		"clear_ip_address": {
			existingContent: "1.2.3.4",
			expectedContent: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "ip")
			if testCase.existingContent != "" {
				const permission = os.FileMode(0o664)
				err := os.WriteFile(path, []byte(testCase.existingContent), permission)
				require.NoError(t, err)
			}

			err := persistPublicIP(path, testCase.content, os.Getuid(), os.Getgid())
			require.NoError(t, err)

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))
		})
	}
}
