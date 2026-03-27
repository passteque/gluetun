package custom

import (
	"errors"
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

var ErrVPNTypeNotSupported = errors.New("VPN type not supported for custom provider")

// GetConnection gets the connection from the OpenVPN configuration file.
func (p *Provider) GetConnection(selection settings.ServerSelection, _ bool) (
	connection models.Connection, err error,
) {
	switch selection.VPN {
	case vpn.OpenVPN:
		return getOpenVPNConnection(p.extractor, selection)
	case vpn.Wireguard, vpn.AmneziaWg:
		return getWireguardConnection(selection), nil
	default:
		return connection, fmt.Errorf("%w: %s", ErrVPNTypeNotSupported, selection.VPN)
	}
}

func getOpenVPNConnection(extractor Extractor,
	selection settings.ServerSelection) (
	connection models.Connection, err error,
) {
	_, connection, err = extractor.Data(*selection.OpenVPN.ConfFile)
	if err != nil {
		return connection, fmt.Errorf("extracting connection: %w", err)
	}

	customPort := *selection.OpenVPN.CustomPort
	if customPort > 0 {
		connection.Port = customPort
	}

	// assume all custom provider servers support port forwarding
	connection.PortForward = true
	if len(selection.Names) > 0 {
		// Set the server name for PIA port forwarding code used
		// together with the custom provider.
		connection.ServerName = selection.Names[0]
	}

	return connection, nil
}

func getWireguardConnection(selection settings.ServerSelection) (
	connection models.Connection,
) {
	connection = models.Connection{
		Type:        vpn.Wireguard,
		IP:          selection.Wireguard.EndpointIP,
		Port:        *selection.Wireguard.EndpointPort,
		Protocol:    constants.UDP,
		PubKey:      selection.Wireguard.PublicKey,
		PortForward: true, // assume all custom provider servers support port forwarding
	}
	if len(selection.Names) > 0 {
		// Set the server name for PIA port forwarding code used
		// together with the custom provider.
		connection.ServerName = selection.Names[0]
	}
	return connection
}
