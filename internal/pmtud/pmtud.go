package pmtud

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/pmtud/icmp"
	"github.com/qdm12/gluetun/internal/pmtud/tcp"
)

// PathMTUDiscover discovers the maximum MTU using both ICMP and TCP.
// Multiple ICMP addresses and TCP addresses can be specified for redundancy.
// ICMP PMTUD is run first. If successful, the range of possible MTU values to
// check for TCP PMTUD is reduced to [maxMTU-150, maxMTU] where maxMTU is the
// maximum MTU found with ICMP PMTUD. Otherwise, TCP PMTUD is run with the
// whole range of possible MTU values up to the physical link MTU to check.
// If the physicalLinkMTU is zero, it defaults to 1500 which is the ethernet standard MTU.
// If the pingTimeout is zero, it defaults to 1 second.
// If the logger is nil, a no-op logger is used.
// It returns [ErrMTUNotFound] if the MTU could not be determined.
func PathMTUDiscover(ctx context.Context, icmpAddrs []netip.Addr, tcpAddrs []netip.AddrPort,
	physicalLinkMTU uint32, tryTimeout time.Duration, fw tcp.Firewall, logger Logger) (
	mtu uint32, err error,
) {
	if physicalLinkMTU == 0 {
		const ethernetStandardMTU = 1500
		physicalLinkMTU = ethernetStandardMTU
	}
	if tryTimeout == 0 {
		tryTimeout = time.Second
	}
	if logger == nil {
		logger = &noopLogger{}
	}

	// Try finding the MTU using ICMP
	maxPossibleMTU := physicalLinkMTU
	icmpSuccess := false
	for _, icmpIP := range icmpAddrs {
		mtu, err := icmp.PathMTUDiscover(ctx, icmpIP, physicalLinkMTU,
			tryTimeout, logger)
		switch {
		case err == nil:
			logger.Debugf("ICMP path MTU discovery against %s found maximum valid MTU %d", icmpIP, mtu)
			icmpSuccess = true
			maxPossibleMTU = mtu
		case errors.Is(err, icmp.ErrNotPermitted), errors.Is(err, icmp.ErrMTUNotFound):
			logger.Debugf("ICMP path MTU discovery failed: %s", err)
		default:
			return 0, fmt.Errorf("ICMP path MTU discovery: %w", err)
		}
		if icmpSuccess {
			break
		}
	}

	minMTU := constants.MinIPv4MTU
	if tcpAddrs[0].Addr().Is6() {
		minMTU = constants.MinIPv6MTU
	}
	if icmpSuccess {
		const mtuMargin = 150
		minMTU = max(maxPossibleMTU-mtuMargin, minMTU)
	}
	mtu, err = tcp.PathMTUDiscover(ctx, tcpAddrs, minMTU, maxPossibleMTU, tryTimeout, fw, logger)
	if err != nil {
		if errors.Is(err, iptables.ErrMarkMatchModuleMissing) {
			logger.Debugf("aborting TCP path MTU discovery: %s", err)
			if icmpSuccess {
				return maxPossibleMTU, nil // only rely on ICMP PMTUD results
			}
		}
		if icmpSuccess {
			return 0, fmt.Errorf("PMTUD succeeded with ICMP but failed with TCP "+
				"- discarding ICMP obtained MTU %d", maxPossibleMTU)
		}
		return 0, errors.New("PMTUD failed with both ICMP and TCP")
	}
	logger.Debugf("TCP path MTU discovery found maximum valid MTU %d", mtu)
	return mtu, nil
}
