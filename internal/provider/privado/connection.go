package privado

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	defaults := utils.NewConnectionDefaults(1194, 1194, 0) //nolint:mnd
	return utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.connPicker)
}
