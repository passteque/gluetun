package pmtud

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	pconstants "github.com/qdm12/gluetun/internal/pmtud/constants"
)

// MaxTheoreticalVPNMTU returns the theoretical maximum MTU for a VPN tunnel
// given the VPN type, network protocol, and VPN gateway IP address.
// This is notably useful to skip testing MTU values higher than this value.
// The function panics if the network or VPN type is unknown.
func MaxTheoreticalVPNMTU(vpnType, network string, vpnGateway netip.Addr) uint32 {
	const physicalLinkMTU = pconstants.MaxEthernetFrameSize
	vpnLinkMTU := physicalLinkMTU
	if vpnGateway.Is4() {
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
	default:
		panic("unknown VPN type: " + vpnType)
	}
	return vpnLinkMTU
}
