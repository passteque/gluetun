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

	// Check each route for IPv6 due to Podman bug listing IPv4 routes
	// as IPv6 routes at container start, see:
	// https://github.com/qdm12/gluetun/issues/1241#issuecomment-1333405949
	level = IPv6Unsupported
	for _, route := range routes {
		link, err := n.LinkByIndex(route.LinkIndex)
		if err != nil {
			return IPv6Unsupported, fmt.Errorf("finding link corresponding to route: %w", err)
		}

		sourceIsIPv4 := route.Src.IsValid() && route.Src.Addr().Is4()
		destinationIsIPv4 := route.Dst.IsValid() && route.Dst.Addr().Is4()
		destinationIsIPv6 := route.Dst.IsValid() && route.Dst.Addr().Is6()
		switch {
		case sourceIsIPv4 && destinationIsIPv4,
			destinationIsIPv6 && route.Dst.Addr().IsLoopback():
		case route.Dst.Addr().IsUnspecified(): // default ipv6 route
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
		default: // non-default ipv6 route found
			n.debugLogger.Debugf("IPv6 is supported by link %s", link.Name)
			level = IPv6Supported
		}
	}

	if level == IPv6Unsupported {
		n.debugLogger.Debugf("no IPv6 route found in %d routes", len(routes))
	}
	return level, nil
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
