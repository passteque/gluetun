package routing

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

func ipIsPrivate(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func ipMatchesFamily(ip netip.Addr, family uint8) bool {
	return (family == netlink.FamilyV4 && ip.Is4()) ||
		(family == netlink.FamilyV6 && ip.Is6())
}

func (r *Routing) AssignedIP(interfaceName string, family uint8) (ip netip.Addr, err error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ip, fmt.Errorf("network interface %s not found: %w", interfaceName, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ip, fmt.Errorf("listing interface %s addresses: %w", interfaceName, err)
	}
	for _, address := range addresses {
		switch value := address.(type) {
		case *net.IPAddr:
			ip = netIPToNetipAddress(value.IP)
		case *net.IPNet:
			ip = netIPToNetipAddress(value.IP)
		default:
			continue
		}

		if !ipMatchesFamily(ip, family) {
			continue
		}

		return ip, nil
	}
	return ip, fmt.Errorf("IP address not found for interface: interface %s in %d addresses",
		interfaceName, len(addresses))
}
