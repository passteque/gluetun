package routing

import (
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

type LocalNetwork struct {
	IPNet         netip.Prefix
	InterfaceName string
	IP            netip.Addr
}

func (r *Routing) LocalNetworks() (localNetworks []LocalNetwork, err error) {
	links, err := r.netLinker.LinkList()
	if err != nil {
		return localNetworks, fmt.Errorf("listing links: %w", err)
	}

	localLinks := make(map[uint32]struct{})

	for _, link := range links {
		if link.DeviceType != netlink.DeviceTypeEthernet {
			continue
		}

		localLinks[link.Index] = struct{}{}
		r.logger.Info("local ethernet link found: " + link.Name)
	}

	if len(localLinks) == 0 {
		return localNetworks, fmt.Errorf("local link not found: in %d links", len(links))
	}

	routes, err := r.netLinker.RouteList(netlink.FamilyAll)
	if err != nil {
		return localNetworks, fmt.Errorf("listing routes: %w", err)
	}

	for _, route := range routes {
		if route.Table != tableMain ||
			(route.Gw.IsValid() && !route.Gw.IsUnspecified()) ||
			(route.Dst.IsValid() && route.Dst.Addr().IsUnspecified()) {
			continue
		} else if _, ok := localLinks[route.LinkIndex]; !ok {
			continue
		}

		var localNet LocalNetwork

		localNet.IPNet = route.Dst
		r.logger.Info("local ipnet found: " + localNet.IPNet.String())

		link, err := r.netLinker.LinkByIndex(route.LinkIndex)
		if err != nil {
			return localNetworks, fmt.Errorf("finding link at index %d: %w", route.LinkIndex, err)
		}

		localNet.InterfaceName = link.Name

		family := netlink.FamilyV6
		if localNet.IPNet.Addr().Is4() {
			family = netlink.FamilyV4
		}
		ip, err := r.AssignedIP(localNet.InterfaceName, family)
		if err != nil {
			return localNetworks, err
		}

		localNet.IP = ip

		localNetworks = append(localNetworks, localNet)
	}

	if len(localNetworks) == 0 {
		return localNetworks, fmt.Errorf("local subnet not found: in %d routes", len(routes))
	}

	return localNetworks, nil
}

func (r *Routing) AddLocalRules(subnets []LocalNetwork) (err error) {
	for _, subnet := range subnets {
		// The main table is a built-in value for Linux, see "man 8 ip-route"
		const mainTable = 254

		// Local has higher priority then outbound(99) and inbound(100) as the
		// local routes might be necessary to reach the outbound/inbound routes.
		const localPriority uint32 = 98

		// Main table was setup correctly by Docker, just need to add rules to use it
		src := netip.Prefix{}
		err = r.addIPRule(src, subnet.IPNet, mainTable, localPriority)
		if err != nil {
			return fmt.Errorf("adding rule: %v: %w", subnet.IPNet, err)
		}
	}
	return nil
}
