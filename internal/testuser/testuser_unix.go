//go:build linux || darwin

package testuser

import (
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RunCasesAsNonRoot runs the calling test again in a child process, owned by
// an unprivileged user. It does nothing when the current process does not run
// as root, since the cases are then already run as a regular user.
//
// The calling test must be a top level one, and must skip the cases needing
// root in the child process, and the cases needing no privilege when running
// as root. Otherwise the same case is asserted twice, in spite of the fact
// root bypasses the file permission checks.
//
// The output of the child process is only logged when it fails, and the
// coverage of the child process is not recorded.
func RunCasesAsNonRoot(t *testing.T) {
	t.Helper()

	// The child process never runs as root, hence never runs itself again.
	if os.Geteuid() != 0 {
		return
	}

	username, uid, gid, err := lookupUnprivileged()
	if err != nil {
		t.Skipf("looking up an unprivileged user: %s", err)
		return
	}

	// The child process cannot write in a temporary directory of the current
	// process, since such a directory belongs to root and its parent
	// directories cannot be traversed by another user.
	temporaryPath, err := os.MkdirTemp("", "testuser-")
	require.NoError(t, err)
	require.NoError(t, os.Chown(temporaryPath, int(uid), int(gid)))
	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(temporaryPath))
	})

	arguments := []string{
		"-test.run=^" + t.Name() + "$",
		"-test.v=true",
	}
	if deadline, ok := t.Deadline(); ok {
		arguments = append(arguments, "-test.timeout="+time.Until(deadline).String())
	}

	executablePath := copyBinary(t, temporaryPath, uid, gid)
	command := exec.CommandContext(t.Context(), executablePath, arguments...)
	command.Dir = temporaryPath
	command.Env = append(os.Environ(), "TMPDIR="+temporaryPath)
	// The supplementary groups are left untouched, since the field type is
	// specific to each operating system and the cases only write files owned
	// by this unprivileged user.
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("running the test as user %s: %s\noutput:\n%s", username, err, output)
	}
}

// copyBinary copies the test binary of the current process, since this binary
// is only readable and executable by the user running the tests.
func copyBinary(t *testing.T, directoryPath string, uid, gid uint32) (childPath string) {
	t.Helper()

	executablePath, err := os.Executable()
	require.NoError(t, err)
	content, err := os.ReadFile(executablePath)
	require.NoError(t, err)

	const (
		name       = "child.test"
		permission = fs.FileMode(0o700)
	)
	childPath = filepath.Join(directoryPath, name)
	//nolint:gosec // The path is in a directory created by this very test.
	require.NoError(t, os.WriteFile(childPath, content, permission))
	// The mode is set again, since writing the file is subject to the umask.
	require.NoError(t, os.Chmod(childPath, permission))
	require.NoError(t, os.Chown(childPath, int(uid), int(gid)))

	return childPath
}

// lookupUnprivileged looks up the unprivileged user to run the child process
// as. The identifier of this user is not hardcoded, since it differs between
// operating systems.
func lookupUnprivileged() (username string, uid, gid uint32, err error) {
	const name = "nobody"
	account, err := user.Lookup(name)
	if err != nil {
		return "", 0, 0, err
	}
	uid64, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", 0, 0, err
	}
	gid64, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return "", 0, 0, err
	}

	return name, uint32(uid64), uint32(gid64), nil
}
