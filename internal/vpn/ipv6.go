package vpn

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/netlink"
)

func (l *Loop) isIPv6Used(settings settings.VPN) bool {
	if !l.ipv6SupportLevel.IsSupported() {
		return false
	}
	switch settings.Type {
	case vpn.AmneziaWg:
		for _, prefix := range settings.AmneziaWg.Wireguard.Addresses {
			if prefix.Addr().Is6() {
				return true
			}
		}
		return false
	case vpn.Custom:
		return l.linkHasPublicIPv6(settings.CustomVPN.Interface)
	case vpn.OpenVPN:
		return l.linkHasPublicIPv6(settings.OpenVPN.Interface)
	case vpn.Wireguard:
		for _, prefix := range settings.Wireguard.Addresses {
			if prefix.Addr().Is6() {
				return true
			}
		}
		return false
	default:
		panic("vpn type not implemented: " + settings.Type)
	}
}

func (l *Loop) linkHasPublicIPv6(vpnInterface string) bool {
	link, err := l.netLinker.LinkByName(vpnInterface)
	if err != nil {
		l.logger.Warnf("assuming IPv6 is not supported, cannot get VPN link by name: %v", err)
		return false
	}
	ipv6Prefixes, err := l.netLinker.AddrList(link.Index, netlink.FamilyV6)
	if err != nil {
		l.logger.Warnf("assuming IPv6 is not supported, cannot list VPN link addresses: %v", err)
		return false
	}
	for _, prefix := range ipv6Prefixes {
		if prefix.Addr().IsGlobalUnicast() && !prefix.Addr().IsPrivate() {
			return true
		}
	}
	return false
}
