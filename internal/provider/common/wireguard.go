package common

import (
	"context"
	"net/netip"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/wireguard"
)

type Firewall interface {
	AcceptOutput(ctx context.Context, protocol, intf string, ip netip.Addr, port uint16, remove bool) error
}

type WireguardConfiger interface {
	WireguardConfig(ctx context.Context, connection *models.Connection,
		settings settings.VPN, wireguardSettings wireguard.Settings,
		fw Firewall) (wireguard.Settings, error)
}
