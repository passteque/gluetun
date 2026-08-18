package customvpn

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
)

// pollTunnelReady signals the ready channel exactly once, when the tunnel
// network interface exists, carries at least one address, AND a route
// through it is installed. It is used when no ready line regular expression
// is set, since the output of a custom VPN binary cannot be relied upon by
// default to detect the tunnel readiness.
//
// The route is part of the condition because everything the tunnel-up path
// does afterwards needs it: path MTU discovery lists the routes of the
// interface to set their MSS, and port forwarding reads the VPN gateway out
// of them. A client that adds its address and installs its route a moment
// later would otherwise be declared ready in between, and both would fail on
// a tunnel that is in fact about to work.
func (r *Runner) pollTunnelReady(ctx context.Context, ready chan<- struct{}) {
	const pollPeriod = 200 * time.Millisecond
	timer := time.NewTimer(pollPeriod)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		if r.tunnelIsUp() {
			select {
			case ready <- struct{}{}:
			case <-ctx.Done():
			}
			return
		}

		timer.Reset(pollPeriod)
	}
}

func (r *Runner) tunnelIsUp() bool {
	link, err := r.netLinker.LinkByName(r.settings.Interface)
	if err != nil {
		return false
	}
	addresses, err := r.netLinker.AddrList(link.Index, netlink.FamilyAll)
	if err != nil || len(addresses) == 0 {
		return false
	}
	routes, err := r.netLinker.RouteList(netlink.FamilyAll)
	if err != nil {
		return false
	}
	for _, route := range routes {
		if route.LinkIndex == link.Index {
			return true
		}
	}
	return false
}
