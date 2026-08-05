package storage

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_copyServer(t *testing.T) {
	t.Parallel()

	server := models.Server{
		Country: "a",
		IPs:     []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
	}

	serverCopy := copyServer(server)

	assert.Equal(t, server, serverCopy)
	// Check for mutation
	serverCopy.IPs[0] = netip.AddrFrom4([4]byte{9, 9, 9, 9})
	serverCopy.PortsTCP = []uint16{80}
	serverCopy.PortsUDP = []uint16{53}
	assert.NotEqual(t, server.IPs, serverCopy.IPs)
	assert.NotEqual(t, server.PortsTCP, serverCopy.PortsTCP)
	assert.NotEqual(t, server.PortsUDP, serverCopy.PortsUDP)
}
