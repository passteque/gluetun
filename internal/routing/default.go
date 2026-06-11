package routing

import (
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

type DefaultRoute struct {
	NetInterface string
	Gateway      netip.Addr
	AssignedIP   netip.Addr
	Family       uint8
}

func (d DefaultRoute) String() string {
	return fmt.Sprintf("interface %s, gateway %s, assigned IP %s and family %s",
		d.NetInterface, d.Gateway, d.AssignedIP, netlink.FamilyToString(d.Family))
}

func (r *Routing) DefaultRoutes() (defaultRoutes []DefaultRoute, err error) {
	routes, err := r.netLinker.RouteList(netlink.FamilyAll)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}

	for _, route := range routes {
		if route.Table != tableMain {
			// ignore non-main table
			continue
		}
		if route.Dst.IsValid() && !route.Dst.Addr().IsUnspecified() {
			continue
		}
		defaultRoute := DefaultRoute{
			Gateway: route.Gw,
			Family:  route.Family,
		}
		linkIndex := route.LinkIndex
		link, err := r.netLinker.LinkByIndex(linkIndex)
		if err != nil {
			return nil, fmt.Errorf("obtaining link by index: for default route at index %d: %w", linkIndex, err)
		}
		defaultRoute.NetInterface = link.Name
		family := netlink.FamilyV6
		if route.Gw.Is4() {
			family = netlink.FamilyV4
		}
		defaultRoute.AssignedIP, err = r.AssignedIP(defaultRoute.NetInterface, family)
		if err != nil {
			return nil, fmt.Errorf("getting assigned IP of %s: %w", defaultRoute.NetInterface, err)
		}

		r.logger.Info("default route found: " + defaultRoute.String())
		defaultRoutes = append(defaultRoutes, defaultRoute)
	}

	if len(defaultRoutes) == 0 {
		return nil, fmt.Errorf("default route not found: in %d route(s)", len(routes))
	}

	return defaultRoutes, nil
}

func DefaultRoutesInterfaces(defaultRoutes []DefaultRoute) (interfaces []string) {
	interfaces = make([]string, len(defaultRoutes))
	for i := range defaultRoutes {
		interfaces[i] = defaultRoutes[i].NetInterface
	}
	return interfaces
}
