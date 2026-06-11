package utils

import (
	"net/http"
	"net/netip"
)

// PortForwardObjects contains fields that may or may not need to be set
// depending on the port forwarding provider code.
type PortForwardObjects struct {
	// Logger is a logger, used by both Private Internet Access and ProtonVPN.
	Logger Logger
	// Gateway is the VPN gateway IP address, used by Private Internet Access
	// and ProtonVPN.
	Gateway netip.Addr
	// InternalIP is the VPN internal IP address assigned, used by Perfect Privacy.
	InternalIP netip.Addr
	// Client is used to query the VPN gateway for Private Internet Access.
	Client *http.Client
	// ServerName is used by Private Internet Access for port forwarding.
	ServerName string
	// CanPortForward is used by Private Internet Access for port forwarding.
	CanPortForward bool
	// Username is used by Private Internet Access for port forwarding.
	Username string
	// Password is used by Private Internet Access for port forwarding.
	Password string
	// PortsCount is used by ProtonVPN for port forwarding.
	PortsCount uint16
}

type Routing interface {
	VPNLocalGatewayIP(vpnInterface string) (gateway netip.Addr, err error)
}
