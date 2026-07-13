//go:build linux

package vpn

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newPhysicalDialContext(mark uint32) func(context.Context, string, string) (net.Conn, error) {
	const connectionTimeout = 30 * time.Second
	dialer := &net.Dialer{
		Timeout:   connectionTimeout,
		KeepAlive: connectionTimeout,
		Control: func(_, _ string, rawConnection syscall.RawConn) error {
			var setMarkErr error
			controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
				// Wireguard's inverted policy rule ignores packets carrying its
				// firewall mark, so these sockets use the physical main route.
				setMarkErr = unix.SetsockoptInt(int(fileDescriptor),
					unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			})
			return errors.Join(controlErr, setMarkErr)
		},
	}
	return dialer.DialContext
}
