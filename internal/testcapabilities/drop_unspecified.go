//go:build !linux

package testcapabilities

import "testing"

// Drop always skips the test, since capabilities are specific to Linux.
func Drop(t *testing.T, _, _, _ bool) {
	t.Helper()
	t.Skip("capabilities are specific to Linux")
}
