//go:build linux || darwin

package tun

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Setup(t *testing.T) {
	t.Parallel()

	path := getTempPath(t)

	defer func() {
		err := os.RemoveAll(path)
		require.NoError(t, err)
	}()

	// No file check fail
	err := check(path)
	require.Error(t, err)
	expectedMessage := "TUN device is not available: open " + path + ": no such file or directory"
	require.Equal(t, expectedMessage, err.Error())

	// Create simple file
	file, err := os.Create(path)
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)

	// Simple file check fail
	err = check(path)
	require.Error(t, err)
	expectedMessage = "TUN file has an unexpected rdev: 0 instead of expected 2760"
	require.Equal(t, expectedMessage, err.Error())

	// Create TUN device fail as file exists
	err = create(path)
	require.Error(t, err)
	require.EqualError(t, err, "creating TUN device file node: file exists")

	// Remove simple file
	err = os.Remove(path)
	require.NoError(t, err)

	// Create TUN device success
	err = create(path)
	if err != nil && strings.HasSuffix(err.Error(), "operation not permitted") {
		t.Skip("You do not have root privileges to create a TUN device, skipping test")
		return
	}
	require.NoError(t, err)

	// Check TUN device success
	err = check(path)
	require.NoError(t, err)
}

func getTempPath(t *testing.T) (path string) {
	t.Helper()
	file, err := os.CreateTemp("", "")
	require.NoError(t, err)
	path = file.Name()
	err = file.Close()
	require.NoError(t, err)
	err = os.Remove(path)
	require.NoError(t, err)
	return path
}
