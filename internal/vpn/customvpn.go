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
// VPN endpoint settings and is only used to allow the VPN connection
// through the firewall, since the custom VPN binary handles the whole
// tunnel setup itself.
func setupCustomVPN(ctx context.Context, fw Firewall, netLinker NetLinker,
	settings settings.VPN, starter Cmder, logger customvpn.Logger) (
	runner *customvpn.Runner, connection models.Connection, err error,
) {
	err = tun.Setup()
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("setting up tun device: %w", err)
	}

	connection = models.Connection{
		Type:     vpn.Custom,
		IP:       settings.CustomVPN.EndpointIP,
		Port:     settings.CustomVPN.EndpointPort,
		Protocol: settings.CustomVPN.EndpointProtocol,
	}

	err = fw.SetVPNConnection(ctx, connection, settings.CustomVPN.Interface)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("allowing VPN connection through firewall: %w", err)
	}

	runner = customvpn.NewRunner(settings.CustomVPN, starter, netLinker, logger)

	return runner, connection, nil
}
