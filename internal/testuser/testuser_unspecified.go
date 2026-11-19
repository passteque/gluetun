//go:build !linux && !darwin

package testuser

import "testing"

// RunCasesAsNonRoot is not implemented, since running the child process as
// another user is specific to unix operating systems.
func RunCasesAsNonRoot(t *testing.T) {
	t.Skip("running the test as another user is not supported on this platform")
}
