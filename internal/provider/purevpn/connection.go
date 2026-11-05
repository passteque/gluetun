package purevpn

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	// Ports only used by servers which do not define any port of their own.
	// The Wireguard port is left undefined: the updater only provides OpenVPN
	// servers, and no Wireguard port is known to be valid for PureVPN.
	defaults := utils.NewConnectionDefaults(80, 15021, 0) //nolint:mnd
	return utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.connPicker)
}
