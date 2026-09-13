package updater

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addData_wireguard(t *testing.T) {
	t.Parallel()

	region := regionData{
		Name:        "CA Vancouver",
		DNS:         "ca-vancouver.privacy.network",
		PortForward: true,
	}
	region.Servers.UDP = []serverData{{
		IP: netip.MustParseAddr("198.51.100.1"),
		CN: "vancouver-openvpn",
	}}
	region.Servers.WG = []serverData{{
		IP: netip.MustParseAddr("198.51.100.2"),
		CN: "vancouver439",
	}}
	serversByName := make(nameToServer)

	changed := addData([]regionData{region}, serversByName)
	require.True(t, changed)
	servers := serversByName.toServersSlice()
	require.Len(t, servers, 2)

	serverByVPN := make(map[string]models.Server, len(servers))
	for _, server := range servers {
		serverByVPN[server.VPN] = server
	}
	wireguardServer := serverByVPN[vpn.Wireguard]
	assert.Equal(t, "vancouver439", wireguardServer.ServerName)
	assert.Equal(t, region.Name, wireguardServer.Region)
	assert.Equal(t, region.DNS, wireguardServer.Hostname)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("198.51.100.2")}, wireguardServer.IPs)
	assert.True(t, wireguardServer.PortForward)
	assert.True(t, wireguardServer.WireguardDynamic)
	assert.False(t, wireguardServer.TCP)
	assert.False(t, wireguardServer.UDP)
}
