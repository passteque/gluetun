package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Service_writePortForwardedFile(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		existingContent string
		ports           []uint16
		expectedLog     string
		expectedContent string
	}{
		"single_port": {
			ports:           []uint16{1000},
			expectedLog:     "writing port file ",
			expectedContent: "1000",
		},
		"multiple_ports": {
			existingContent: "3000",
			ports:           []uint16{1000, 2000},
			expectedLog:     "writing port file ",
			expectedContent: "1000\n2000",
		},
		"clear_ports": {
			existingContent: "1000\n2000",
			expectedLog:     "clearing port file ",
			expectedContent: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			path := filepath.Join(t.TempDir(), "forwarded_port")
			if testCase.existingContent != "" {
				const permission = os.FileMode(0o664)
				err := os.WriteFile(path, []byte(testCase.existingContent), permission)
				require.NoError(t, err)
			}

			logger := NewMockLogger(ctrl)
			logger.EXPECT().Info(testCase.expectedLog + path)

			service := &Service{
				settings: Settings{Filepath: path},
				puid:     os.Getuid(),
				pgid:     os.Getgid(),
				logger:   logger,
			}

			err := service.writePortForwardedFile(testCase.ports)
			require.NoError(t, err)

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))
		})
	}
}
