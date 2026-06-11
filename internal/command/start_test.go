package command

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func linesToReadCloser(lines []string) io.ReadCloser {
	s := strings.Join(lines, "\n")
	return io.NopCloser(bytes.NewBufferString(s))
}

func Test_start(t *testing.T) {
	t.Parallel()

	errDummy := errors.New("dummy")

	testCases := map[string]struct {
		stdout        []string
		stdoutPipeErr error
		stderr        []string
		stderrPipeErr error
		startErr      error
		waitErr       error
		err           error
	}{
		"no output": {},
		"success": {
			stdout: []string{"hello", "world"},
			stderr: []string{"some", "error"},
		},
		"stdout pipe error": {
			stdoutPipeErr: errDummy,
			err:           errDummy,
		},
		"stderr pipe error": {
			stderrPipeErr: errDummy,
			err:           errDummy,
		},
		"start error": {
			startErr: errDummy,
			err:      errDummy,
		},
		"wait error": {
			waitErr: errDummy,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			stdout := linesToReadCloser(testCase.stdout)
			stderr := linesToReadCloser(testCase.stderr)

			mockCmd := NewMockexecCmd(ctrl)

			mockCmd.EXPECT().StdoutPipe().
				Return(stdout, testCase.stdoutPipeErr)
			if testCase.stdoutPipeErr == nil {
				mockCmd.EXPECT().StderrPipe().Return(stderr, testCase.stderrPipeErr)
				if testCase.stderrPipeErr == nil {
					mockCmd.EXPECT().Start().Return(testCase.startErr)
					if testCase.startErr == nil {
						mockCmd.EXPECT().Wait().Return(testCase.waitErr)
					}
				}
			}

			stdoutLines, stderrLines, waitError, err := start(mockCmd)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
				assert.Nil(t, stdoutLines)
				assert.Nil(t, stderrLines)
				assert.Nil(t, waitError)
				return
			}

			require.NoError(t, err)

			collectAndCheckChannels(t, stdoutLines, stderrLines, waitError,
				testCase.stdout, testCase.stderr, testCase.waitErr)
		})
	}
}

func collectAndCheckChannels(t *testing.T, stdoutLines, stderrLines <-chan string,
	waitError <-chan error, expectedStdout, expectedStderr []string, expectedWaitErr error,
) {
	t.Helper()

	stdoutIndex := 0
	stderrIndex := 0

	done := false
	for !done {
		select {
		case line, ok := <-stdoutLines:
			if !ok {
				stdoutLines = nil
				continue
			}
			assert.Equal(t, expectedStdout[stdoutIndex], line)
			stdoutIndex++
		case line, ok := <-stderrLines:
			if !ok {
				stderrLines = nil
				continue
			}
			assert.Equal(t, expectedStderr[stderrIndex], line)
			stderrIndex++
		case err := <-waitError:
			if expectedWaitErr != nil {
				require.Error(t, err)
				assert.Equal(t, expectedWaitErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			done = true
		}
	}

	assert.Equal(t, len(expectedStdout), stdoutIndex)
	assert.Equal(t, len(expectedStderr), stderrIndex)
}
