package privateinternetaccess

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	// Set port defaults depending on encryption preset.
	defaults := utils.NewConnectionDefaults(0, 0, 1337)
	if selection.OpenVPN.PIAEncPreset != nil {
		switch *selection.OpenVPN.PIAEncPreset {
		case presets.Normal:
			defaults.OpenVPNTCPPort = 502
			defaults.OpenVPNUDPPort = 1198
		case presets.Strong:
			defaults.OpenVPNTCPPort = 8443
			defaults.OpenVPNUDPPort = 8080
		}
	}

	return utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.connPicker)
}
