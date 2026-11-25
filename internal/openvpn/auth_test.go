//go:build linux || darwin

package openvpn

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/testcapabilities"
	"github.com/qdm12/gluetun/internal/testuser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Configurator_WriteAuthFile(t *testing.T) {
	t.Parallel()

	// The group is not one of the process groups, as for a PGID set by the user.
	otherUID, otherGID := testuser.UnrelatedOwner(t)
	processUID, processGID := os.Geteuid(), os.Getegid()

	testCases := map[string]struct {
		rootOnly bool
		// existing is the content of a file created beforehand, if not empty.
		existing           string
		existingMode       fs.FileMode
		existingUID        int
		existingGID        int
		puid               int
		withoutChown       bool
		withoutFowner      bool
		withoutDACOverride bool
		errWrapped         error
		errMessage         string
		expectedRewritten  bool
	}{
		"fresh_write": {
			puid:              processUID,
			expectedRewritten: true,
		},
		"unchanged_content": {
			existing:     "user\npassword",
			existingMode: 0o440,
			existingUID:  processUID,
			existingGID:  processGID,
			puid:         processUID,
		},
		"changed_content": {
			existing:          "olduser\noldpassword",
			existingMode:      0o440,
			existingUID:       processUID,
			existingGID:       processGID,
			puid:              processUID,
			expectedRewritten: true,
		},
		"changed_permissions": {
			existing:          "user\npassword",
			existingMode:      0o644,
			existingUID:       processUID,
			existingGID:       processGID,
			puid:              processUID,
			expectedRewritten: true,
		},
		"restart_without_capabilities": {
			rootOnly:           true,
			existing:           "user\npassword",
			existingMode:       0o440,
			existingUID:        otherUID,
			existingGID:        processGID,
			puid:               otherUID,
			withoutChown:       true,
			withoutFowner:      true,
			withoutDACOverride: true,
		},
		"changed_owner": {
			rootOnly:          true,
			existing:          "user\npassword",
			existingMode:      0o440,
			existingUID:       processUID,
			existingGID:       processGID,
			puid:              otherUID,
			expectedRewritten: true,
		},
		"changed_group": {
			rootOnly:          true,
			existing:          "user\npassword",
			existingMode:      0o440,
			existingUID:       processUID,
			existingGID:       otherGID,
			puid:              processUID,
			expectedRewritten: true,
		},
		"restart_changed_content_with_chown_only": {
			rootOnly:           true,
			existing:           "olduser\noldpassword",
			existingMode:       0o440,
			existingUID:        otherUID,
			existingGID:        processGID,
			puid:               otherUID,
			withoutFowner:      true,
			withoutDACOverride: true,
			expectedRewritten:  true,
		},
		// Older versions wrote the file owned by puid and pgid with 0400.
		"older_version_file_with_chown_only": {
			rootOnly:           true,
			existing:           "user\npassword",
			existingMode:       0o400,
			existingUID:        otherUID,
			existingGID:        otherGID,
			puid:               otherUID,
			withoutFowner:      true,
			withoutDACOverride: true,
			expectedRewritten:  true,
		},
		// OpenVPN could not read the file again as puid.
		"fresh_write_without_chown": {
			rootOnly:     true,
			puid:         otherUID,
			withoutChown: true,
			errWrapped:   fs.ErrPermission,
			errMessage:   "setting file ownership: chown ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if testCase.rootOnly && os.Geteuid() != 0 {
				t.Skip("changing the ownership of a file to another user needs root")
			}

			path := filepath.Join(t.TempDir(), "auth.conf")
			// Modification time in the past to check if the file is rewritten.
			oldModTime := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
			if testCase.existing != "" {
				err := os.WriteFile(path, []byte(testCase.existing), testCase.existingMode)
				require.NoError(t, err)
				// chmod explicitly since WriteFile is subject to the umask
				err = os.Chmod(path, testCase.existingMode)
				require.NoError(t, err)
				err = os.Chtimes(path, oldModTime, oldModTime)
				require.NoError(t, err)
				err = os.Chown(path, testCase.existingUID, testCase.existingGID)
				require.NoError(t, err)
			}

			configurator := &Configurator{
				authFilePath: path,
				puid:         testCase.puid,
				pgid:         otherGID,
			}

			if testCase.withoutChown || testCase.withoutFowner || testCase.withoutDACOverride {
				testcapabilities.Drop(t, testCase.withoutChown, testCase.withoutFowner, testCase.withoutDACOverride)
			}

			err := configurator.WriteAuthFile("user", "password")

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}

			info := assertFile(t, path, "user\npassword", testCase.puid, processGID)
			rewritten := !oldModTime.Equal(info.ModTime())
			assert.Equal(t, testCase.expectedRewritten, rewritten)
		})
	}
}

func Test_Configurator_WriteAskPassFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "askpass")
	configurator := &Configurator{
		askPassPath: path,
		puid:        os.Geteuid(),
	}

	err := configurator.WriteAskPassFile("passphrase")
	require.NoError(t, err)

	assertFile(t, path, "passphrase", os.Geteuid(), os.Getegid())
}

func assertFile(t *testing.T, path, expectedContent string, expectedUID, expectedGID int) fs.FileInfo {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, expectedContent, string(content))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o440), info.Mode().Perm())
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, expectedUID, int(stat.Uid))
	assert.Equal(t, expectedGID, int(stat.Gid))
	return info
}
