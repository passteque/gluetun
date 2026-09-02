package privateinternetaccess

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

// GetWireguardConnection obtains a live PIA Wireguard registration endpoint.
// The embedded PIA server list only contains OpenVPN servers.
func (p *Provider) GetWireguardConnection(ctx context.Context, selection settings.ServerSelection,
	restrictedClient common.RestrictedClient,
) (connection models.Connection, err error) {
	if restrictedClient == nil {
		return connection, errors.New("restricted network client is not set")
	}

	const serverListHostname = "serverlist.piaservers.net"
	client, cleanup, err := restrictedClient.OpenHTTPSByHostname(ctx,
		net.JoinHostPort(serverListHostname, "443"))
	if err != nil {
		return connection, fmt.Errorf("opening PIA server list connection: %w", err)
	}
	defer cleanupRestrictedConnection(cleanup, &err)

	liveUpdater := updater.New(client)
	servers, err := liveUpdater.FetchWireguardServers(ctx, selection)
	if err != nil {
		return connection, fmt.Errorf("fetching Wireguard servers: %w", err)
	}

	connections := make([]models.Connection, 0, len(servers))
	for _, server := range servers {
		for _, ip := range server.IPs {
			connections = append(connections, models.Connection{
				Type:        vpn.Wireguard,
				IP:          ip,
				Port:        wireguardRegistrationPort,
				Protocol:    constants.UDP,
				Hostname:    server.Hostname,
				ServerName:  server.ServerName,
				PortForward: server.PortForward,
			})
		}
	}
	return p.connPicker.PickConnection(connections, selection)
}

func cleanupRestrictedConnection(cleanup func() error, err *error) {
	cleanupErr := cleanup()
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("cleaning up restricted connection: %w", cleanupErr)
		*err = errors.Join(*err, cleanupErr)
	}
}

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	// Set port defaults depending on encryption preset.
	var defaults utils.ConnectionDefaults
	if selection.VPN == vpn.Wireguard {
		defaults.WireguardPort = wireguardRegistrationPort
		return utils.GetConnection(p.Name(),
			p.storage, selection, defaults, ipv6Supported, p.connPicker)
	}

	switch *selection.OpenVPN.PIAEncPreset {
	case presets.Normal:
		defaults.OpenVPNTCPPort = 502
		defaults.OpenVPNUDPPort = 1198
	case presets.Strong:
		defaults.OpenVPNTCPPort = 8443
		defaults.OpenVPNUDPPort = 8080
	}

	return utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.connPicker)
}
