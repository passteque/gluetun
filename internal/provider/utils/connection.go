package utils

import (
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

type ConnectionDefaults struct {
	OpenVPNTCPPort uint16
	OpenVPNUDPPort uint16
	WireguardPort  uint16
}

func NewConnectionDefaults(openvpnTCPPort, openvpnUDPPort,
	wireguardPort uint16,
) ConnectionDefaults {
	return ConnectionDefaults{
		OpenVPNTCPPort: openvpnTCPPort,
		OpenVPNUDPPort: openvpnUDPPort,
		WireguardPort:  wireguardPort,
	}
}

type Storage interface {
	FilterServers(provider string, selection settings.ServerSelection) (
		servers []models.Server, err error)
}

func GetConnection(provider string,
	storage Storage,
	selection settings.ServerSelection,
	defaults ConnectionDefaults,
	ipv6Supported bool,
	connPicker *ConnectionPicker,
) (
	connection models.Connection, err error,
) {
	servers, err := storage.FilterServers(provider, selection)
	if err != nil {
		return connection, fmt.Errorf("filtering servers: %w", err)
	}

	// Randomize order of the servers struct so the first connection to be picked
	// won't always be the same one.
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	protocol := getProtocol(selection)

	connections := make([]models.Connection, 0, len(servers))
	for _, server := range servers {
		for _, ip := range server.IPs {
			if !ipv6Supported && ip.Is6() {
				continue
			}

			port := getPort(selection, server, defaults.OpenVPNTCPPort,
				defaults.OpenVPNUDPPort, defaults.WireguardPort)

			hostname := server.Hostname
			if selection.VPN == vpn.OpenVPN && server.OvpnX509 != "" {
				// For Windscribe where hostname and
				// OpenVPN x509 are not the same.
				hostname = server.OvpnX509
			}

			connection := models.Connection{
				Type:        selection.VPN,
				IP:          ip,
				Port:        port,
				Protocol:    protocol,
				Hostname:    hostname,
				ServerName:  server.ServerName,
				PortForward: server.PortForward,
				PubKey:      server.WgPubKey, // Wireguard
			}
			connections = append(connections, connection)
		}
	}

	slices.SortStableFunc(connections, func(a, b models.Connection) int {
		aIPv6 := a.IP.Is6()
		bIPv6 := b.IP.Is6()
		switch {
		case aIPv6 && !bIPv6:
			return -1
		case !aIPv6 && bIPv6:
			return 1
		default:
			return 0
		}
	})

	return pickConnection(connections, selection, connPicker)
}
