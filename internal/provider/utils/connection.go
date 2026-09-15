package utils

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
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

	ordered := selection.Mode == "ordered"
	switch selection.Mode {
	case "random":
		// Randomize order of the servers struct so the first connection to be picked
		// won't always be the same one.
		rand.Shuffle(len(servers), func(i, j int) {
			servers[i], servers[j] = servers[j], servers[i]
		})
	case "ordered":
		// Sort the servers by the priority given by the order of the values
		// in the narrowest set server selection filter list, so the first
		// list values are picked first, with the next ones as fallbacks.
		sortServersByTier(servers, selection)
	default:
		panic("unknown server selection mode: " + selection.Mode)
	}

	protocol := getProtocol(selection)
	port := getPort(selection, defaults.OpenVPNTCPPort,
		defaults.OpenVPNUDPPort, defaults.WireguardPort)

	connections := make([]models.Connection, 0, len(servers))
	for _, server := range servers {
		if ordered {
			// Prefer the IPv6 IP addresses of the server,
			// like the final sort of the random mode.
			slices.SortStableFunc(server.IPs, ipv6First(netip.Addr.Is6))
		}

		for _, ip := range server.IPs {
			if !ipv6Supported && ip.Is6() {
				continue
			}

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

	if !ordered {
		slices.SortStableFunc(connections, ipv6First(func(c models.Connection) bool {
			return c.IP.Is6()
		}))
	}

	return pickConnection(connections, selection, connPicker)
}

// ipv6First returns a stable sort comparison function that
// orders the items with IPv6 addresses first.
func ipv6First[T any](isIPv6 func(item T) bool) func(a, b T) int {
	return func(a, b T) int {
		aIPv6 := isIPv6(a)
		bIPv6 := isIPv6(b)
		switch {
		case aIPv6 && !bIPv6:
			return -1
		case !aIPv6 && bIPv6:
			return 1
		default:
			return 0
		}
	}
}
