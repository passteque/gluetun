//go:build linux || darwin

package openvpn

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/qdm12/gluetun/internal/testuser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Configurator_WriteConfig(t *testing.T) {
	t.Parallel()

	testuser.RunCasesAsNonRoot(t)

	// The mode is not asserted, since WriteConfig does not change it and
	// the mode of a file it creates depends on the umask of the process.
	testCases := map[string]struct {
		// rootOnly is set for cases changing the ownership of a file to
		// another user, which needs root.
		rootOnly bool
		// nonRootOnly is set for cases relying on the chown being refused,
		// which root is allowed to do.
		nonRootOnly bool
		// existing is the content of an existing file, owned by existingUID
		// and existingGID, and no file is created beforehand when empty.
		existing        string
		existingUID     int
		existingGID     int
		lines           []string
		ownerUID        int
		ownerGID        int
		expectedErr     error
		expectedContent string
		expectedUID     int
		expectedGID     int
	}{
		"create_file": {
			lines:           []string{"option-a value", "option-b value"},
			ownerUID:        os.Getuid(),
			ownerGID:        os.Getgid(),
			expectedContent: "option-a value\noption-b value",
			expectedUID:     os.Getuid(),
			expectedGID:     os.Getgid(),
		},
		"overwrite_file_of_self": {
			existing:        "outdated value\n",
			existingUID:     os.Getuid(),
			existingGID:     os.Getgid(),
			lines:           []string{"option-a value"},
			ownerUID:        os.Getuid(),
			ownerGID:        os.Getgid(),
			expectedContent: "option-a value",
			expectedUID:     os.Getuid(),
			expectedGID:     os.Getgid(),
		},
		// The file system of the container is kept across restarts, so the
		// file is often already owned by the wanted owner. The chown is then
		// not attempted, which is what lets a run with CAP_CHOWN dropped
		// write the configuration file.
		"overwrite_file_already_owned_by_target": {
			rootOnly:        true,
			existing:        "outdated value\n",
			existingUID:     os.Getuid() + 1,
			existingGID:     os.Getgid() + 1,
			lines:           []string{"option-a value"},
			ownerUID:        os.Getuid() + 1,
			ownerGID:        os.Getgid() + 1,
			expectedContent: "option-a value",
			expectedUID:     os.Getuid() + 1,
			expectedGID:     os.Getgid() + 1,
		},
		"create_file_for_other_user": {
			rootOnly:        true,
			lines:           []string{"option-a value"},
			ownerUID:        os.Getuid() + 1,
			ownerGID:        os.Getgid() + 1,
			expectedContent: "option-a value",
			expectedUID:     os.Getuid() + 1,
			expectedGID:     os.Getgid() + 1,
		},
		"chown_not_permitted": {
			nonRootOnly:     true,
			lines:           []string{"option-a value"},
			ownerUID:        os.Getuid() + 1,
			ownerGID:        os.Getgid() + 1,
			expectedErr:     fs.ErrPermission,
			expectedContent: "option-a value",
			expectedUID:     os.Getuid(),
			expectedGID:     os.Getgid(),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			isRoot := os.Geteuid() == 0
			switch {
			case testCase.rootOnly && !isRoot:
				t.Skip("root is needed to change the ownership of a file to another user")
			case testCase.nonRootOnly && isRoot:
				t.Skip("root is allowed to change the ownership of a file")
			}

			configPath := filepath.Join(t.TempDir(), "config.ovpn")
			if testCase.existing != "" {
				// The mode is the safest one, since it is not asserted and
				// WriteConfig leaves the mode of an existing file unchanged.
				err := os.WriteFile(configPath, []byte(testCase.existing), 0o600)
				require.NoError(t, err)
				err = os.Chown(configPath, testCase.existingUID, testCase.existingGID)
				require.NoError(t, err)
			}

			configurator := &Configurator{
				configPath: configPath,
				puid:       testCase.ownerUID,
				pgid:       testCase.ownerGID,
			}

			err := configurator.WriteConfig(testCase.lines)

			assert.ErrorIs(t, err, testCase.expectedErr)

			data, err := os.ReadFile(configPath)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))

			info, err := os.Stat(configPath)
			require.NoError(t, err)
			stat, ok := info.Sys().(*syscall.Stat_t)
			require.True(t, ok, "the file information of a file on Linux or darwin is a *syscall.Stat_t")
			assert.Equal(t, testCase.expectedUID, int(stat.Uid))
			assert.Equal(t, testCase.expectedGID, int(stat.Gid))
		})
	}
}
