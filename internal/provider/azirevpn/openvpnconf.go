package azirevpn

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
)

func (p *Provider) OpenVPNConfig(_ models.Connection,
	_ settings.OpenVPN, _ bool,
) (lines []string) {
	return nil
}
