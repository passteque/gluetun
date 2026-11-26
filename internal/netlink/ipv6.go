package netlink

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type IPv6SupportLevel uint8

const (
	IPv6Unsupported = iota
	// IPv6Supported indicates the host supports IPv6 but has no access to the
	// Internet via IPv6. It is true if one IPv6 route is found and no default
	// IPv6 route is found.
	IPv6Supported
	// IPv6Internet indicates the host has access to the Internet via IPv6,
	// which is detected when a default IPv6 route is found.
	IPv6Internet
)

func (i IPv6SupportLevel) IsSupported() bool {
	return i == IPv6Supported || i == IPv6Internet
}

func (n *NetLink) FindIPv6SupportLevel(ctx context.Context,
	checkAddresses []netip.AddrPort, firewall Firewall,
) (level IPv6SupportLevel, err error) {
	routes, err := n.RouteList(FamilyV6)
	if err != nil {
		return IPv6Unsupported, fmt.Errorf("listing IPv6 routes: %w", err)
	}

	level = IPv6Unsupported
	for _, route := range routes {
		if !isIPv6SupportEvidence(route) {
			continue
		}

		link, err := n.LinkByIndex(route.LinkIndex)
		if err != nil {
			return IPv6Unsupported, fmt.Errorf("finding link corresponding to default IPv6 route: %w", err)
		}

		if route.Dst.IsValid() && !route.Dst.Addr().IsUnspecified() { // non-default ipv6 route
			n.debugLogger.Debugf("IPv6 is supported by link %s", link.Name)
			level = IPv6Supported
			continue
		}

		n.debugLogger.Debugf("IPv6 default route found on link %s", link.Name)
		for _, checkAddress := range checkAddresses {
			err = dialAddrThroughFirewall(ctx, link.Name, checkAddress, firewall)
			if err != nil {
				n.debugLogger.Debugf("IPv6 query to %s through %s failed: %s",
					checkAddress, link.Name, err)
				level = IPv6Supported
				continue
			}
			n.debugLogger.Debugf("IPv6 internet is accessible through link %s", link.Name)
			return IPv6Internet, nil
		}
	}

	if level == IPv6Unsupported {
		n.debugLogger.Debugf("no IPv6 route found in %d routes", len(routes))
	}
	return level, nil
}

// isIPv6SupportEvidence reports whether a route is an evidence that the host
// can deliver IPv6 packets to a remote host. The kernel adds a link local
// fe80::/64 route and a ff00::/8 multicast route on every IPv6 enabled
// interface, and these say nothing about IPv6 connectivity. Configuring IPv6
// on such a host black-holes IPv6 traffic, instead of making it fail fast.
// See https://github.com/passteque/gluetun/issues/3561
func isIPv6SupportEvidence(route Route) bool {
	sourceIsIPv4 := route.Src.IsValid() && route.Src.Addr().Is4()
	if sourceIsIPv4 {
		// Due to a Podman bug listing IPv4 routes as IPv6 routes at container
		// start, see https://github.com/qdm12/gluetun/issues/1241#issuecomment-1333405949
		return false
	}

	if isUnusableRouteType(route.Type) {
		// Skip routes that can never deliver packets, in particular
		// `unreachable default dev lo` routes that some kernels install
		// in containers without IPv6. The netlink library synthesizes a
		// `::/0` destination for them, and `::` is the unspecified
		// address, not the loopback one, so they would otherwise be
		// wrongly counted as IPv6 support.
		// See: https://github.com/qdm12/gluetun/issues/3444
		return false
	}

	if !route.Dst.IsValid() {
		// The default ::/0 route has no destination attribute.
		return true
	}

	destination := route.Dst.Addr()
	switch {
	case !destination.Is6(),
		destination.IsLoopback(),
		destination.IsLinkLocalUnicast(),
		destination.IsMulticast():
		return false
	default:
		return true
	}
}

// isUnusableRouteType reports whether a route of the given type can
// never deliver packets, and therefore cannot be evidence of IPv6
// support.
func isUnusableRouteType(routeType uint8) bool {
	switch routeType {
	case routeTypeUnreachable, routeTypeProhibit, routeTypeBlackhole:
		return true
	default:
		return false
	}
}

func dialAddrThroughFirewall(ctx context.Context, intf string,
	checkAddress netip.AddrPort, firewall Firewall,
) (err error) {
	const protocol = "tcp"
	remove := false
	err = firewall.AcceptOutput(ctx, protocol, intf,
		checkAddress.Addr(), checkAddress.Port(), remove)
	if err != nil {
		return fmt.Errorf("accepting output traffic: %w", err)
	}
	defer func() {
		remove = true
		firewallErr := firewall.AcceptOutput(ctx, protocol, intf,
			checkAddress.Addr(), checkAddress.Port(), remove)
		if err == nil && firewallErr != nil {
			err = fmt.Errorf("removing output traffic rule: %w", firewallErr)
		}
	}()

	dialer := &net.Dialer{
		Timeout: time.Second,
	}
	conn, err := dialer.DialContext(ctx, protocol, checkAddress.String())
	if err != nil {
		return fmt.Errorf("dialing: %w", err)
	}
	err = conn.Close()
	if err != nil {
		return fmt.Errorf("closing connection: %w", err)
	}

	return nil
}
