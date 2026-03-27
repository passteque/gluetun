package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

var ErrNoConnectionToPickFrom = errors.New("no connection to pick from")

// pickConnection picks a connection from a pool of connections.
// If the VPN protocol is Wireguard and the target IP is set,
// it finds the connection corresponding to this target IP.
// Otherwise, it picks a random connection from the pool of connections
// and sets the target IP address as the IP if this one is set.
func pickConnection(connections []models.Connection,
	selection settings.ServerSelection, randSource rand.Source) (
	connection models.Connection, err error,
) {
	if len(connections) == 0 {
		return connection, ErrNoConnectionToPickFrom
	}

	var targetIP netip.Addr
	switch selection.VPN {
	case vpn.OpenVPN:
		targetIP = selection.OpenVPN.EndpointIP
	case vpn.Wireguard, vpn.AmneziaWg:
		targetIP = selection.Wireguard.EndpointIP
	default:
		panic("unknown VPN type: " + selection.VPN)
	}
	targetIPSet := targetIP.IsValid() && !targetIP.IsUnspecified()

	if targetIPSet && selection.VPN == vpn.Wireguard {
		// we need the right public key
		return getTargetIPConnection(connections, targetIP)
	}

	connection = pickRandomConnection(connections, randSource)
	if targetIPSet {
		connection.IP = targetIP
	}

	return connection, nil
}

func pickRandomConnection(connections []models.Connection,
	source rand.Source,
) models.Connection {
	return connections[rand.New(source).Intn(len(connections))] //nolint:gosec
}

var errTargetIPNotFound = errors.New("target IP address not found")

func getTargetIPConnection(connections []models.Connection,
	targetIP netip.Addr,
) (connection models.Connection, err error) {
	for _, connection := range connections {
		if targetIP == connection.IP {
			return connection, nil
		}
	}
	return connection, fmt.Errorf("%w: in %d filtered connections",
		errTargetIPNotFound, len(connections))
}
