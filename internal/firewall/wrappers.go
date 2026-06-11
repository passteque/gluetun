package firewall

import (
	"context"
	"net/netip"
)

func (c *Config) Version(ctx context.Context) (version string, err error) {
	return c.impl.Version(ctx)
}

// TempDropOutputTCPRST temporarily drops outgoing TCP RST packets to the specified address and port,
// for any TCP packets not marked with the excludeMark given.
// This is necessary for TCP path MTU discovery to work, as the kernel will try to terminate the connection
// by sending a TCP RST packet, although we want to handle the connection manually.
func (c *Config) TempDropOutputTCPRST(ctx context.Context,
	src, dst netip.AddrPort, excludeMark int) (
	revert func(ctx context.Context) error, err error,
) {
	return c.impl.TempDropOutputTCPRST(ctx, src, dst, excludeMark)
}

func (c *Config) AcceptOutput(ctx context.Context, protocol, intf string,
	ip netip.Addr, port uint16, remove bool,
) error {
	return c.impl.AcceptOutput(ctx, protocol, intf, ip, port, remove)
}
