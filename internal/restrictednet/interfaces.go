package restrictednet

import (
	"context"
	"net/netip"
)

type Firewall interface {
	AcceptOutputFromIPPortToIPPort(ctx context.Context,
		protocol, intf string, source, destination netip.AddrPort, remove bool,
	) error
}
