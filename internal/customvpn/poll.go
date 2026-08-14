package customvpn

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
)

// pollTunnelReady signals the ready channel exactly once, when the
// tunnel network interface exists with at least one address assigned.
// It is used when no ready line regular expression is set, since the
// output of a custom VPN binary cannot be relied upon by default to
// detect the tunnel readiness.
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
	return err == nil && len(addresses) > 0
}
