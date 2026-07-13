//go:build !linux

package vpn

import (
	"context"
	"net"
	"time"
)

func newPhysicalDialContext(_ uint32) func(context.Context, string, string) (net.Conn, error) {
	const connectionTimeout = 30 * time.Second
	dialer := &net.Dialer{
		Timeout:   connectionTimeout,
		KeepAlive: connectionTimeout,
	}
	return dialer.DialContext
}
