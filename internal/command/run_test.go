package command

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func Test_run(t *testing.T) {
	t.Parallel()

	errDummy := errors.New("dummy")

	testCases := map[string]struct {
		stdout []byte
		cmdErr error
		output string
		err    error
	}{
		"no output": {},
		"cmd error": {
			stdout: []byte("'hello \nworld'\n"),
			cmdErr: errDummy,
			output: "hello \nworld",
			err:    errDummy,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			mockCmd := NewMockexecCmd(ctrl)

			mockCmd.EXPECT().CombinedOutput().Return(testCase.stdout, testCase.cmdErr)

			output, err := run(mockCmd)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.output, output)
		})
	}
}
