package statusfile

import "testing"

func dropCapabilities(t *testing.T, _, _ bool) {
	t.Helper()
	t.Skip("capabilities are specific to Linux")
}
