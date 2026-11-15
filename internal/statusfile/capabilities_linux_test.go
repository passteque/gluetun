package statusfile

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// dropCapabilities drops CAP_CHOWN and/or CAP_FOWNER from the effective
// capabilities of the thread running the test, as in a container running
// without them. The test goroutine is left locked to its thread, so the
// thread is terminated with the test instead of being reused.
func dropCapabilities(t *testing.T, chown, fowner bool) {
	t.Helper()

	runtime.LockOSThread()

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	// The capabilities are split in two sets of 32 bits,
	// the first one holding both CAP_CHOWN and CAP_FOWNER.
	var data [2]unix.CapUserData
	err := unix.Capget(&header, &data[0])
	require.NoError(t, err)

	if chown {
		data[0].Effective &^= 1 << unix.CAP_CHOWN
	}
	if fowner {
		data[0].Effective &^= 1 << unix.CAP_FOWNER
	}
	err = unix.Capset(&header, &data[0])
	require.NoError(t, err)
}
