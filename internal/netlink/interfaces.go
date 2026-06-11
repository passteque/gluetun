package netlink

import (
	"context"
	"net/netip"

	"github.com/qdm12/log"
)

type DebugLogger interface {
	Debug(message string)
	Debugf(format string, args ...any)
	Patch(options ...log.Option)
}

type Firewall interface {
	AcceptOutput(ctx context.Context, protocol, intf string, ip netip.Addr,
		port uint16, remove bool) (err error)
}
