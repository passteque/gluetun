//go:build linux || darwin

package service

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Service_writePortForwardedFile(t *testing.T) {
	t.Parallel()

	type owner struct{ uid, gid int }
	self := owner{uid: os.Getuid(), gid: os.Getgid()}
	// other is a user other than the one running the test.
	other := owner{uid: self.uid + 1, gid: self.gid + 1}

	testCases := map[string]struct {
		// rootOnly is set for cases changing the ownership of the file to
		// another user, which needs root.
		rootOnly bool
		// nonRootOnly is set for cases relying on a chown not being
		// permitted, which it always is for root.
		nonRootOnly      bool
		missingDirectory bool
		existingContent  string
		ports            []uint16
		owner            owner
		expectedLog      string
		chownWarning     bool
		expectedErr      error
		expectedContent  string
		expectedOwner    owner
	}{
		"single_port": {
			ports:           []uint16{1000},
			owner:           self,
			expectedLog:     "writing port file ",
			expectedContent: "1000",
			expectedOwner:   self,
		},
		"multiple_ports": {
			existingContent: "3000",
			ports:           []uint16{1000, 2000},
			owner:           self,
			expectedLog:     "writing port file ",
			expectedContent: "1000\n2000",
			expectedOwner:   self,
		},
		"clear_ports": {
			existingContent: "1000\n2000",
			owner:           self,
			expectedLog:     "clearing port file ",
			expectedContent: "",
			expectedOwner:   self,
		},
		"chown_to_other_user": {
			rootOnly:        true,
			existingContent: "3000",
			ports:           []uint16{1000},
			owner:           other,
			expectedLog:     "writing port file ",
			expectedContent: "1000",
			expectedOwner:   other,
		},
		"chown_not_permitted": {
			nonRootOnly:     true,
			existingContent: "3000",
			ports:           []uint16{1000},
			owner:           other,
			expectedLog:     "writing port file ",
			chownWarning:    true,
			expectedContent: "1000",
			expectedOwner:   self,
		},
		"missing_directory": {
			missingDirectory: true,
			ports:            []uint16{1000},
			owner:            self,
			expectedLog:      "writing port file ",
			expectedErr:      fs.ErrNotExist,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			isRoot := os.Geteuid() == 0
			switch {
			case testCase.rootOnly && !isRoot:
				t.Skip("root is needed to change the ownership of a file to another user")
			case testCase.nonRootOnly && isRoot:
				t.Skip("root is always permitted to chown")
			}

			path := filepath.Join(t.TempDir(), "forwarded_port")
			if testCase.missingDirectory {
				path = filepath.Join(t.TempDir(), "missing", "forwarded_port")
			}

			if testCase.existingContent != "" {
				const existingPermission = fs.FileMode(0o644)
				err := os.WriteFile(path, []byte(testCase.existingContent), existingPermission)
				require.NoError(t, err)
				err = os.Chown(path, self.uid, self.gid)
				require.NoError(t, err)
			}

			logger := NewMockLogger(ctrl)
			logger.EXPECT().Info(testCase.expectedLog + path)
			if testCase.chownWarning {
				logger.EXPECT().Warn("file ownership not set: chown " + path + ": operation not permitted" +
					", CAP_CHOWN is required")
			}

			service := &Service{
				settings: Settings{Filepath: path},
				puid:     testCase.owner.uid,
				pgid:     testCase.owner.gid,
				logger:   logger,
			}

			err := service.writePortForwardedFile(testCase.ports)

			assert.ErrorIs(t, err, testCase.expectedErr)
			if testCase.expectedErr != nil {
				return
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))

			info, err := os.Stat(path)
			require.NoError(t, err)
			const expectedPermission = fs.FileMode(0o664)
			assert.Equal(t, expectedPermission, info.Mode().Perm())
			stat, ok := info.Sys().(*syscall.Stat_t)
			require.True(t, ok, "the file information of a file on Linux or darwin is a *syscall.Stat_t")
			actualOwner := owner{uid: int(stat.Uid), gid: int(stat.Gid)}
			assert.Equal(t, testCase.expectedOwner, actualOwner)
		})
	}
}
