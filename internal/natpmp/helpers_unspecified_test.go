//go:build !linux && !darwin

package natpmp

import "testing"

// reserveClosedPort is not implemented on this platform.
func reserveClosedPort(t *testing.T) (port uint16) {
	t.Helper()
	panic("not implemented")
}
