package pmtud

import (
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	pconstants "github.com/qdm12/gluetun/internal/pmtud/constants"
)

// MaxTheoreticalVPNMTU returns the theoretical maximum MTU for a VPN tunnel
// given the VPN type, network protocol, and whether IPv6 is used.
// This is notably useful to skip testing MTU values higher than this value.
// It is an upper bound for the path MTU search, so it does not have to match
// the tunnel's real overhead, which is why the custom VPN type subtracts no
// VPN header at all.
// The function panics if the network or VPN type is unknown.
func MaxTheoreticalVPNMTU(vpnType, network string, ipv6 bool) uint32 {
	const physicalLinkMTU = pconstants.MaxEthernetFrameSize
	vpnLinkMTU := physicalLinkMTU
	if !ipv6 {
		vpnLinkMTU -= pconstants.IPv4HeaderLength
	} else {
		vpnLinkMTU -= pconstants.IPv6HeaderLength
	}
	switch network {
	case constants.TCP:
		vpnLinkMTU -= pconstants.BaseTCPHeaderLength
	case constants.UDP:
		vpnLinkMTU -= pconstants.UDPHeaderLength
	default:
		panic("unknown network protocol: " + network)
	}
	switch vpnType {
	case vpn.Wireguard, vpn.AmneziaWg:
		vpnLinkMTU -= pconstants.WireguardHeaderLength
	case vpn.OpenVPN:
		vpnLinkMTU -= pconstants.OpenVPNHeaderMaxLength
	case vpn.Custom:
		// The tunnel overhead of a custom VPN binary is unknown, so nothing
		// is subtracted for it: this value is the CEILING of the path MTU
		// binary search, not a computed MTU, and the search finds the real
		// one by probing. Overestimating the ceiling costs a few probes;
		// underestimating it hides MTU values that actually work.
	default:
		panic("unknown VPN type: " + vpnType)
	}
	return vpnLinkMTU
}
