//go:build linux

package nftables

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_Version(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		output        string
		runError      error
		expected      string
		expectedError string
	}{
		"success": {
			output:   "nftables v1.1.5",
			expected: "nftables v1.1.5",
		},
		"success_with_trailing_whitespace": {
			output:   "nftables v1.1.5\n",
			expected: "nftables v1.1.5",
		},
		"empty_output": {
			output:        "   \n",
			expectedError: "nft version string is empty",
		},
		"run_error": {
			runError:      errors.New("exec failed"),
			expectedError: "running nft --version: exec failed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockRunner := NewMockCmdRunner(ctrl)
			f := &Firewall{runner: mockRunner}

			var captured *exec.Cmd
			mockRunner.EXPECT().Run(gomock.Any()).DoAndReturn(
				func(cmd *exec.Cmd) (string, error) {
					captured = cmd
					return testCase.output, testCase.runError
				},
			)

			version, err := f.Version(t.Context())

			// The command must be `nft --version`.
			requireCmd(t, captured, "nft", "--version")

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, version)
		})
	}
}

func requireCmd(t *testing.T, cmd *exec.Cmd, expected ...string) {
	t.Helper()
	if cmd == nil {
		assert.Fail(t, "expected a command to be run")
		return
	}
	assert.Equal(t, expected, cmd.Args)
}
