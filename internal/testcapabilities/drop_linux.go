//go:build linux

package testcapabilities

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Drop drops CAP_CHOWN, CAP_FOWNER and/or CAP_DAC_OVERRIDE from the
// effective capabilities of the thread running the test, as in a container
// running without them. Only the effective set is cleared, since it is the
// one the kernel checks to grant or deny an operation; the permitted set is
// left untouched, which is of no consequence since nothing re-enables the
// dropped capabilities and the thread dies with the test.
// The test goroutine is left locked to its thread, so the thread is
// terminated with the test instead of being reused by another one. Note
// that the threads the runtime creates on behalf of this one inherit the
// reduced capabilities, which is of no consequence here since every test
// case drops what it needs before writing a file.
func Drop(t *testing.T, chown, fowner, dacOverride bool) {
	t.Helper()

	runtime.LockOSThread()

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	// The capabilities are split in two sets of 32 bits, the first one
	// holding CAP_CHOWN, CAP_FOWNER and CAP_DAC_OVERRIDE.
	var data [2]unix.CapUserData
	err := unix.Capget(&header, &data[0])
	require.NoError(t, err)

	if chown {
		data[0].Effective &^= 1 << unix.CAP_CHOWN
	}
	if fowner {
		data[0].Effective &^= 1 << unix.CAP_FOWNER
	}
	if dacOverride {
		data[0].Effective &^= 1 << unix.CAP_DAC_OVERRIDE
	}
	err = unix.Capset(&header, &data[0])
	require.NoError(t, err)
}
