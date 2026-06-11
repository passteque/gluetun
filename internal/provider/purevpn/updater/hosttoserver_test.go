package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hostToServer_add_obfuscationRespectsProtocolAndPort(t *testing.T) {
	t.Parallel()

	hts := make(hostToServer)
	hts.add("us2-obf-udp.ptoserver.com", false, true, 1210, false)

	server := hts["us2-obf-udp.ptoserver.com"]
	assert.True(t, server.Obfuscated)
	assert.True(t, server.UDP)
	assert.False(t, server.TCP)
	assert.Nil(t, server.TCPPorts)
	assert.Equal(t, []uint16{1210}, server.UDPPorts)
}

func Test_hostToServer_add_obfuscationTCPUsesInventoryPort(t *testing.T) {
	t.Parallel()

	hts := make(hostToServer)
	hts.add("us2-obf-udp.ptoserver.com", true, false, 80, false)

	server := hts["us2-obf-udp.ptoserver.com"]
	assert.True(t, server.TCP)
	assert.Equal(t, []uint16{80}, server.TCPPorts)
}

func Test_hostToServer_add_p2pTagSetsCategory(t *testing.T) {
	t.Parallel()

	hts := make(hostToServer)
	hts.add("us2-udp.ptoserver.com", false, true, 15021, true)

	server := hts["us2-udp.ptoserver.com"]
	assert.Equal(t, []string{"p2p"}, server.Categories)
}
