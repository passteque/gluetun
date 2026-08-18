package vpn

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/customvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/tun"
)

// setupCustomVPN sets the custom VPN binary runner up using the
// settings given. The connection returned is built from the custom
// VPN endpoint settings: it opens the firewall for the connection the
// binary makes, and carries the port-forwarding fields, since the custom
// VPN binary handles the whole tunnel setup itself.
func setupCustomVPN(ctx context.Context, fw Firewall, netLinker NetLinker,
	settings settings.VPN, starter Cmder, logger customvpn.Logger) (
	runner *customvpn.Runner, connection models.Connection, err error,
) {
	err = tun.Setup()
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("setting up tun device: %w", err)
	}

	connection = customVPNConnection(settings)

	err = fw.SetVPNConnection(ctx, connection, settings.CustomVPN.Interface)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("allowing VPN connection through firewall: %w", err)
	}

	runner = customvpn.NewRunner(settings.CustomVPN, starter, netLinker, logger)

	return runner, connection, nil
}

// customVPNConnection builds the connection the firewall opens for and the
// port forwarder works from. Split out of setupCustomVPN so it can be tested
// without a tun device.
func customVPNConnection(settings settings.VPN) (connection models.Connection) {
	connection = models.Connection{
		Type:     vpn.Custom,
		IP:       settings.CustomVPN.EndpointIP,
		Port:     settings.CustomVPN.EndpointPort,
		Protocol: settings.CustomVPN.EndpointProtocol,
		// Port forwarding is not bound to the VPN protocol: each provider
		// implementation only needs the gateway, the assigned IP and its own
		// credentials, all of which come from the tunnel interface. Same
		// assumption the custom provider makes for Wireguard, and
		// PORT_FORWARD_PROVIDER picks the implementation the same way.
		PortForward: true,
	}
	if len(settings.Provider.ServerSelection.Names) > 0 {
		// Private Internet Access port forwarding matches the server by name
		// and panics on an empty one, so carry SERVER_NAMES through exactly
		// as the custom provider does.
		connection.ServerName = settings.Provider.ServerSelection.Names[0]
	}
	return connection
}
