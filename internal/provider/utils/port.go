package utils

import (
	"errors"
	"fmt"
	"slices"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

// getPorts returns the ports to connect to on the server, one for each port
// the server supports for the selected VPN protocol.
// It returns no port when the server does not support the custom port set.
func getPorts(selection settings.ServerSelection, server models.Server,
	defaultOpenVPNTCP, defaultOpenVPNUDP, defaultWireguard uint16,
) (ports []uint16) {
	customPort := getCustomPort(selection)
	switch selection.VPN {
	case vpn.Wireguard:
		// Only a single port is used for Wireguard, defined by the provider.
		return portsForProtocol("Wireguard", customPort, nil, defaultWireguard)
	default: // OpenVPN
		if selection.OpenVPN.Protocol == constants.TCP {
			return portsForProtocol("OpenVPN TCP", customPort, server.TCPPorts, defaultOpenVPNTCP)
		}
		return portsForProtocol("OpenVPN UDP", customPort, server.UDPPorts, defaultOpenVPNUDP)
	}
}

// portsForProtocol returns all the ports of the server, or the default port
// when the server does not define any port for the protocol.
// When a custom port is set, it is the only port returned, and no port is
// returned if the server does not support it.
func portsForProtocol(portName string, customPort uint16, serverPorts []uint16,
	defaultPort uint16,
) (ports []uint16) {
	if customPort > 0 {
		if len(serverPorts) > 0 && !slices.Contains(serverPorts, customPort) {
			return nil
		}
		return []uint16{customPort}
	}

	if len(serverPorts) > 0 {
		return serverPorts
	}

	checkDefined(portName, defaultPort)
	return []uint16{defaultPort}
}

// getCustomPort returns the server endpoint port set by the user,
// or 0 when no custom port is set.
func getCustomPort(selection settings.ServerSelection) (port uint16) {
	switch selection.VPN {
	case vpn.Wireguard:
		return *selection.Wireguard.EndpointPort
	default:
		return *selection.OpenVPN.CustomPort
	}
}

// noConnectionError returns an error indicating no connection could be picked.
func noConnectionError(selection settings.ServerSelection, serversCount int) error {
	customPort := getCustomPort(selection)
	if customPort > 0 {
		return fmt.Errorf("no server supports the custom port %d out of %d filtered servers",
			customPort, serversCount)
	}
	return errors.New("no connection to pick from")
}

func checkDefined(portName string, port uint16) {
	if port > 0 {
		return
	}
	message := fmt.Sprintf("no default %s port is defined!", portName)
	panic(message)
}
