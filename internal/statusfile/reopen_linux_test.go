//go:build linux

package statusfile

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/qdm12/gluetun/internal/testcapabilities"
	"github.com/qdm12/gluetun/internal/testuser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_OpenWritable_restoreOnFailedReopen checks the permissions and the
// ownership changed to reopen a file are restored when the reopen fails.
// The reopen is made to fail by the file being the program a process is
// running of, which the kernel refuses to open for writing.
func Test_OpenWritable_restoreOnFailedReopen(t *testing.T) {
	t.Parallel()

	if os.Geteuid() != 0 {
		t.Skip("root is needed to change the ownership of a file to another user")
	}

	unrelatedUID, unrelatedGID := testuser.UnrelatedOwner(t)

	sleepPath, err := exec.LookPath("sleep")
	require.NoError(t, err)
	// The program may be a symbolic link to a multi-call binary, such as
	// busybox, which then runs the program named by its first argument.
	sleepPath, err = filepath.EvalSymlinks(sleepPath)
	require.NoError(t, err)
	program, err := os.ReadFile(sleepPath)
	require.NoError(t, err)

	testCases := map[string]struct {
		withoutFowner bool
	}{
		"permissions_restored":           {},
		"permissions_and_owner_restored": {withoutFowner: true},
	}

	// The programs are copied and started before the parallel subtests,
	// since a program cannot be started while another process, such as one
	// started at the same time, holds it open for writing.
	paths := make(map[string]string, len(testCases))
	for name := range testCases {
		path := filepath.Join(t.TempDir(), "program")
		const mode = fs.FileMode(0o755)
		err := os.WriteFile(path, program, mode) //nolint:gosec // the file must be executable
		require.NoError(t, err)
		// chmod explicitly since WriteFile is subject to the umask
		err = os.Chmod(path, mode)
		require.NoError(t, err)
		err = os.Chown(path, unrelatedUID, unrelatedGID)
		require.NoError(t, err)

		command := exec.CommandContext(t.Context(), path, "60")
		command.Args[0] = "sleep"
		err = command.Start()
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_ = command.Wait()
		})

		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if !errors.Is(err, syscall.ETXTBSY) {
			if file != nil {
				_ = file.Close()
			}
			t.Skip("the kernel lets a running program be opened for writing")
		}
		paths[name] = path
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := paths[name]
			testcapabilities.Drop(t, false, testCase.withoutFowner, true)

			_, err := OpenWritable(path, 0o664)

			require.ErrorIs(t, err, fs.ErrPermission)
			assert.ErrorContains(t, err,
				"permission denied, CAP_DAC_OVERRIDE, CAP_FOWNER or CAP_CHOWN is required")

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, program, data)

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o755), info.Mode().Perm())
			stat, ok := info.Sys().(*syscall.Stat_t)
			require.True(t, ok, "the file information of a file on Linux is a *syscall.Stat_t")
			assert.Equal(t, unrelatedUID, int(stat.Uid))
			assert.Equal(t, unrelatedGID, int(stat.Gid))
		})
	}
}
