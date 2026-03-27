package wireguard

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/qdm12/gluetun/internal/netlink"
)

func AddRoutes(linkIndex uint32, destinations []netip.Prefix,
	firewallMark uint32, netlinker NetLinker, logger Erroer,
) (err error) {
	for _, dst := range destinations {
		err = addRoute(linkIndex, dst, firewallMark, netlinker)
		if err == nil {
			continue
		}

		if dst.Addr().Is6() && strings.Contains(err.Error(), "permission denied") {
			logger.Errorf("cannot add route for IPv6 due to a permission denial. "+
				"Ignoring and continuing execution; "+
				"Please report to https://github.com/qdm12/gluetun/issues/998 if you find a fix. "+
				"Full error string: %s", err)
			continue
		}
		return fmt.Errorf("adding route for destination %s: %w", dst, err)
	}
	return nil
}

func addRoute(linkIndex uint32, dst netip.Prefix,
	firewallMark uint32, netlinker NetLinker,
) (err error) {
	family := netlink.FamilyV4
	if dst.Addr().Is6() {
		family = netlink.FamilyV6
	}
	route := netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
		Family:    family,
		Table:     firewallMark,
		Type:      netlink.RouteTypeUnicast,
		Scope:     netlink.ScopeUniverse,
		Proto:     netlink.ProtoStatic,
	}

	err = netlinker.RouteAdd(route)
	if err != nil {
		return fmt.Errorf(
			"adding route for link with index %d, destination %s and table %d: %w",
			linkIndex, dst, firewallMark, err)
	}

	return err
}
