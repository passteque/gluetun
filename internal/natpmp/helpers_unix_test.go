//go:build linux || darwin

package natpmp

import (
	"testing"

	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// reserveClosedPort returns a port with no UDP listener, so that UDP
// datagrams sent to it get an ICMP port unreachable message, which surfaces
// on the sender as a connection refused error on read. The port is kept
// reserved, so that the OS cannot assign it to another process, by a TCP
// socket which is bound but not listening: a bound UDP socket would be a UDP
// listener and would receive the datagrams instead of refusing them.
func reserveClosedPort(t *testing.T) (port uint16) {
	t.Helper()

	fd, err := unix.Socket(constants.AF_INET, constants.SOCK_STREAM, constants.IPPROTO_TCP)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := unix.Close(fd)
		assert.NoError(t, err)
	})

	addr := &unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}

	err = unix.Bind(fd, addr)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}

	sockAddr, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}

	sockAddr4, ok := sockAddr.(*unix.SockaddrInet4)
	if !ok {
		_ = unix.Close(fd)
		t.Fatal("not an IPv4 address")
	}

	return uint16(sockAddr4.Port) //nolint:gosec
}
