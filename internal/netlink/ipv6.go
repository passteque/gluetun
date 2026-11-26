package netlink

import (
	"fmt"
)

func (n *NetLink) IsIPv6Supported() (supported bool, err error) {
	routes, err := n.RouteList(FamilyV6)
	if err != nil {
		return false, fmt.Errorf("listing IPv6 routes: %w", err)
	}

	for _, route := range routes {
		if !isIPv6SupportEvidence(route) {
			continue
		}

		link, err := n.LinkByIndex(route.LinkIndex)
		if err != nil {
			return false, fmt.Errorf("finding link corresponding to route: %w", err)
		}

		n.debugLogger.Debugf("IPv6 is supported by link %s", link.Name)
		return true, nil
	}

	n.debugLogger.Debugf("IPv6 is not supported after searching %d routes",
		len(routes))
	return false, nil
}

// isIPv6SupportEvidence reports whether a route is an evidence that the host
// can deliver IPv6 packets to a remote host. The kernel adds a link local
// fe80::/64 route and a ff00::/8 multicast route on every IPv6 enabled
// interface, and these say nothing about IPv6 connectivity. Configuring IPv6
// on such a host black-holes IPv6 traffic, instead of making it fail fast.
// See https://github.com/passteque/gluetun/issues/3561
func isIPv6SupportEvidence(route Route) bool {
	sourceIsIPv4 := route.Src.IsValid() && route.Src.Is4()
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
func isUnusableRouteType(routeType int) bool {
	switch routeType {
	case routeTypeUnreachable, routeTypeProhibit, routeTypeBlackhole:
		return true
	default:
		return false
	}
}
