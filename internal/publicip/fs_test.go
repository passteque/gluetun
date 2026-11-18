//go:build linux || darwin

package publicip

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

func Test_Loop_persistPublicIP(t *testing.T) {
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
		content          string
		owner            owner
		chownWarning     bool
		expectedErr      error
		expectedContent  string
		expectedOwner    owner
	}{
		"write_ip_address": {
			content:         "1.2.3.4",
			owner:           self,
			expectedContent: "1.2.3.4",
			expectedOwner:   self,
		},
		"replace_ip_address": {
			existingContent: "1.2.3.4",
			content:         "::1",
			owner:           self,
			expectedContent: "::1",
			expectedOwner:   self,
		},
		"clear_ip_address": {
			existingContent: "1.2.3.4",
			owner:           self,
			expectedContent: "",
			expectedOwner:   self,
		},
		"chown_to_other_user": {
			rootOnly:        true,
			existingContent: "1.2.3.4",
			content:         "5.6.7.8",
			owner:           other,
			expectedContent: "5.6.7.8",
			expectedOwner:   other,
		},
		"chown_not_permitted": {
			nonRootOnly:     true,
			existingContent: "1.2.3.4",
			content:         "5.6.7.8",
			owner:           other,
			chownWarning:    true,
			expectedContent: "5.6.7.8",
			expectedOwner:   self,
		},
		"missing_directory": {
			missingDirectory: true,
			content:          "1.2.3.4",
			owner:            self,
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

			path := filepath.Join(t.TempDir(), "ip")
			if testCase.missingDirectory {
				path = filepath.Join(t.TempDir(), "missing", "ip")
			}

			if testCase.existingContent != "" {
				const existingPermission = fs.FileMode(0o644)
				err := os.WriteFile(path, []byte(testCase.existingContent), existingPermission)
				require.NoError(t, err)
				err = os.Chown(path, self.uid, self.gid)
				require.NoError(t, err)
			}

			logger := NewMockLogger(ctrl)
			if testCase.chownWarning {
				logger.EXPECT().Warn("file ownership not set: chown " + path + ": operation not permitted" +
					", CAP_CHOWN is required")
			}

			loop := &Loop{
				puid:   testCase.owner.uid,
				pgid:   testCase.owner.gid,
				logger: logger,
			}

			err := loop.persistPublicIP(path, testCase.content)

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
