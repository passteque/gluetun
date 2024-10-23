package ovpn

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (lines []string) {
	providerSettings := utils.OpenVPNProviderSettings{
		AuthUserPass: true,
		Ciphers: []string{
			openvpn.Chacha20Poly1305,
			openvpn.AES256gcm,
			openvpn.AES256cbc,
			openvpn.AES128gcm,
		},
	}
	return utils.OpenVPNConfig(providerSettings, connection, settings, ipv6Supported)
}
