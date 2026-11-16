//go:build !linux

package statusfile

import "testing"

// dropCapabilities always skips the test, since capabilities
// are specific to Linux.
func dropCapabilities(t *testing.T, _, _, _ bool) {
	t.Helper()
	t.Skip("capabilities are specific to Linux")
}
