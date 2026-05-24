package storage

import (
	"slices"

	"github.com/qdm12/gluetun/internal/models"
)

func copyServer(server models.Server) (serverCopy models.Server) {
	serverCopy = server
	serverCopy.IPs = slices.Clone(server.IPs)
	serverCopy.PortsTCP = slices.Clone(server.PortsTCP)
	serverCopy.PortsUDP = slices.Clone(server.PortsUDP)
	return serverCopy
}
