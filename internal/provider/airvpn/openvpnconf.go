package airvpn

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (lines []string) {
	const defaultMTU = 1320               // see https://github.com/qdm12/gluetun/issues/1650#issuecomment-1988298206
	const defaultMSSFix = defaultMTU - 28 // 28 bytes of IPv4 UDP header size
	providerSettings := utils.OpenVPNProviderSettings{
		AuthUserPass:  true,
		RemoteCertTLS: true,
		Auth:          openvpn.SHA512,
		CAs:           []string{"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"}, //nolint:lll
		TLSCrypt:      "a3a7d8f4e778d279d9076a8d47a9aa0c6054aed5752ddefa5efac1ea982740f1ffcabadf0d3709dae18c1fad61e14f72a8eb7cb931ed0209e67c1d325353a657a1198ef649f1c23861a2a19f2c6b27aa5e43be761e0c71e9c2e8d33b75af289effb1b1e4ec603d865f74e2b4348ff631c5c81202d90003ed263dca4022aa9861520e00cc26e40fa171b9985a2763ccb4c63560b7e6b0f897978fb25a2d5889cd6d46a29509fa09830aff18d6e81a8dc1a0182402e3039c3316180e618705ca35f2763f8a62ca5983d145faa2276532ae5e18459a0b729dc67f41b928e592b39467ec3d79c70205595718b1bce56ca4ff58e692ce09c8282d2770d2bf5c217c06",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   //nolint:lll
		MssFix:        defaultMSSFix,
		ExtraLines: []string{
			"comp-lzo no", // Explicitly disable compression
			"push-peer-info",
		},
	}

	switch settings.Version {
	case openvpn.Openvpn25, openvpn.Openvpn27:
		providerSettings.Ciphers = []string{
			openvpn.AES256gcm, openvpn.AES256cbc, openvpn.AES192gcm,
			openvpn.AES192cbc, openvpn.AES128gcm, openvpn.AES128cbc,
			openvpn.Chacha20Poly1305,
		}
	default:
		panic(fmt.Sprintf("openvpn version %q is not implemented", settings.Version))
	}

	providerSettings.SetEnv = map[string]string{"UV_IPV6": "no"}
	if ipv6Supported {
		providerSettings.SetEnv["UV_IPV6"] = "yes"
	}

	return utils.OpenVPNConfig(providerSettings, connection, settings, ipv6Supported)
}
