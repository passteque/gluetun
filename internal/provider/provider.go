package provider

import (
	"context"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
)

// Provider contains methods to read and modify the openvpn configuration to connect as a client.
type Provider interface {
	GetConnection(selection settings.ServerSelection, ipv6Supported bool) (connection models.Connection, err error)
	OpenVPNConfig(connection models.Connection, settings settings.OpenVPN, ipv6Supported bool) (lines []string)
	Name() string
	FetchServers(ctx context.Context, minServers int) (
		servers []models.Server, err error)
}

type RestrictedClient = common.RestrictedClient

// DynamicWireguardProvider obtains a live server, registers a Wireguard key
// and returns provider-generated connection settings. Discovery and
// registration are done for every connection attempt.
type DynamicWireguardProvider interface {
	GetWireguardConnection(ctx context.Context, selection settings.ServerSelection,
		restrictedClient common.RestrictedClient) (connection models.Connection, err error)
	RegisterWireguard(ctx context.Context, connection models.Connection,
		username, password string, restrictedClient common.RestrictedClient) (
		wireguardConnection models.WireguardConnection, err error)
}
