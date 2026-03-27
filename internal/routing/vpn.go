package routing

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

var (
	ErrVPNLocalGatewayIPNotFound       = errors.New("VPN local gateway IP address not found")
	ErrVPNLocalGatewayIPv6NotSupported = errors.New("VPN local gateway IPv6 address not supported")
)

func (r *Routing) VPNLocalGatewayIP(vpnIntf string) (ip netip.Addr, err error) {
	vpnLink, err := r.netLinker.LinkByName(vpnIntf)
	if err != nil {
		return ip, fmt.Errorf("finding link %s: %w", vpnIntf, err)
	}
	vpnLinkIndex := vpnLink.Index

	routes, err := r.netLinker.RouteList(netlink.FamilyAll)
	if err != nil {
		return ip, fmt.Errorf("listing routes: %w", err)
	}
	for _, route := range routes {
		if route.LinkIndex != vpnLinkIndex {
			continue
		}

		switch {
		case route.Dst.IsValid() && route.Dst.Addr().IsUnspecified() && route.Gw.IsValid(): // OpenVPN
			return route.Gw, nil
		case route.Dst.IsSingleIP() &&
			route.Dst.Addr().Compare(route.Src.Addr()) == 0 &&
			route.Table == tableLocal: // Wireguard
			if route.Src.Addr().Is6() {
				return netip.Addr{}, fmt.Errorf("%w: %s", ErrVPNLocalGatewayIPv6NotSupported, route.Src)
			}
			bytes := route.Src.Addr().As4()
			// force last byte to 1 to get the VPN gateway IP
			// This is not necessarily bullet proof but it seems to work.
			bytes[3] = 1
			return netip.AddrFrom4(bytes), nil
		}
	}
	return ip, fmt.Errorf("%w: in %d routes", ErrVPNLocalGatewayIPNotFound, len(routes))
}

var ErrVPNRouteNotFound = errors.New("VPN route not found")

// VPNRoutes returns the routes that are using the VPN interface, excluding local routes
// and link-local multicast and unicast routes.
func (r *Routing) VPNRoutes(vpnIntf string) (routes []netlink.Route, err error) {
	vpnLink, err := r.netLinker.LinkByName(vpnIntf)
	if err != nil {
		return nil, fmt.Errorf("finding link %s: %w", vpnIntf, err)
	}
	vpnLinkIndex := vpnLink.Index

	allRoutes, err := r.netLinker.RouteList(netlink.FamilyAll)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	routes = make([]netlink.Route, 0, len(allRoutes))
	for _, route := range allRoutes {
		const localTable = 255
		switch {
		case route.LinkIndex != vpnLinkIndex,
			route.Table == localTable:
			continue
		case !route.Dst.IsValid(), route.Dst.Addr().IsUnspecified():
			routes = append(routes, route)
		case route.Dst.Addr().IsLinkLocalMulticast(), route.Dst.Addr().IsLinkLocalUnicast():
			continue
		case !route.Dst.Addr().IsPrivate():
			routes = append(routes, route)
		}
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("%w: for interface %s in %d routes",
			ErrVPNRouteNotFound, vpnIntf, len(allRoutes))
	}

	return routes, nil
}
