package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sync"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

// ConnectionPicker is a struct that holds the state of the connection pool cycler.
type ConnectionPicker struct {
	mutex       sync.Mutex
	fingerprint uint64
	nextIndex   uint
}

func NewConnectionPicker() *ConnectionPicker {
	return &ConnectionPicker{}
}

func (c *ConnectionPicker) pickConnection(connections []models.Connection,
) models.Connection {
	fingerprint := fingerprintPool(connections)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.fingerprint != fingerprint || c.nextIndex >= uint(len(connections)) {
		c.fingerprint = fingerprint
		c.nextIndex = 0
	}

	connection := connections[c.nextIndex]
	c.nextIndex++
	if c.nextIndex >= uint(len(connections)) {
		c.nextIndex = 0
	}

	return connection
}

func fingerprintPool(connections []models.Connection) uint64 {
	hasher := fnv.New64a()

	for _, connection := range connections {
		_, _ = hasher.Write([]byte(connection.Type))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write(connection.IP.AsSlice())
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write(binary.BigEndian.AppendUint16(nil, connection.Port))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write([]byte(connection.Protocol))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write([]byte(connection.Hostname))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write([]byte(connection.PubKey))
		_, _ = hasher.Write([]byte("|"))
		_, _ = hasher.Write([]byte(connection.ServerName))
		_, _ = hasher.Write([]byte("|"))
		if connection.PortForward {
			_, _ = hasher.Write([]byte("1"))
		} else {
			_, _ = hasher.Write([]byte("0"))
		}
		_, _ = hasher.Write([]byte("\n"))
	}

	return hasher.Sum64()
}

// pickConnection picks a connection from a pool of connections.
// If the VPN protocol is Wireguard and the target IP is set,
// it finds the connection corresponding to this target IP.
// Otherwise, it cycles through the pool of connections.
// and sets the target IP address as the IP if this one is set.
func pickConnection(connections []models.Connection,
	selection settings.ServerSelection, picker *ConnectionPicker) (
	connection models.Connection, err error,
) {
	if len(connections) == 0 {
		return connection, errors.New("no connection to pick from")
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

	connection = picker.pickConnection(connections)
	if targetIPSet {
		connection.IP = targetIP
	}

	return connection, nil
}

func getTargetIPConnection(connections []models.Connection,
	targetIP netip.Addr,
) (connection models.Connection, err error) {
	for _, connection := range connections {
		if targetIP == connection.IP {
			return connection, nil
		}
	}
	return connection, fmt.Errorf("target IP address not found: in %d filtered connections",
		len(connections))
}
