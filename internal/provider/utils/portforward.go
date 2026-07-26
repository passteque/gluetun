package utils

import (
	"context"
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
	// OnPortsChanged is called by a KeepPortForward implementation when the VPN
	// gateway assigns different external ports whilst refreshing an existing
	// mapping. It updates the firewall, the port forwarded file and runs the up
	// command for the new ports, so that a reassignment does not require tearing
	// down and restarting the whole port forwarding service.
	// It is nil when the port forwarding service does not support reassignment,
	// in which case a KeepPortForward implementation must return an error rather
	// than silently keep forwarding a port the client no longer listens on.
	OnPortsChanged func(ctx context.Context, internalToExternalPorts map[uint16]uint16) error
}

type Routing interface {
	VPNLocalGatewayIP(vpnInterface string) (gateway netip.Addr, err error)
}
