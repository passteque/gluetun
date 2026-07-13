package privateinternetaccess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

// GetWireguardConnection obtains a live PIA Wireguard registration endpoint.
// The embedded PIA server list only contains OpenVPN servers.
func (p *Provider) GetWireguardConnection(ctx context.Context, selection settings.ServerSelection,
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error),
	dialContext func(context.Context, string, string) (net.Conn, error),
	allowConnection func(context.Context, models.Connection) (func(context.Context) error, error),
) (
	connection models.Connection, err error,
) {
	const serverListHostname = "serverlist.piaservers.net"
	const lookupTimeout = 10 * time.Second
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addresses, err := lookupNetIP(lookupCtx, "ip4", serverListHostname)
	if err != nil {
		return connection, fmt.Errorf("resolving PIA server list host: %w", err)
	}
	if len(addresses) == 0 {
		return connection, errors.New("resolving PIA server list host: no IPv4 address found")
	}

	const serverListPort uint16 = 443
	serverListConnection := models.Connection{
		IP:       addresses[0],
		Port:     serverListPort,
		Protocol: constants.TCP,
	}
	removeConnection, err := allowConnection(ctx, serverListConnection)
	if err != nil {
		return connection, fmt.Errorf("allowing PIA server list connection: %w", err)
	}
	defer cleanupTemporaryConnection(ctx, removeConnection, &err)

	client, err := p.newDialingClient(serverListHostname, serverListConnection.IP, dialContext)
	if err != nil {
		return connection, fmt.Errorf("creating PIA server list client: %w", err)
	}
	defer client.CloseIdleConnections()

	liveUpdater := updater.New(client)
	server, err := liveUpdater.FetchWireguardServer(ctx, selection)
	if err != nil {
		return connection, fmt.Errorf("fetching Wireguard server: %w", err)
	}

	return models.Connection{
		Type:        vpn.Wireguard,
		IP:          server.IPs[0],
		Port:        wireguardRegistrationPort,
		Protocol:    constants.UDP,
		Hostname:    server.Hostname,
		ServerName:  server.ServerName,
		PortForward: server.PortForward,
	}, nil
}

func cleanupTemporaryConnection(ctx context.Context, remove func(context.Context) error, err *error) {
	removeErr := remove(context.WithoutCancel(ctx))
	if removeErr != nil {
		removeErr = fmt.Errorf("removing temporary connection allowance: %w", removeErr)
		*err = errors.Join(*err, removeErr)
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
