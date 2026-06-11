package updater

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseLocalData(t *testing.T) {
	t.Parallel()

	content := []byte(`"use strict";module.exports={body:{countries:[{id:1,protocols:[
		{number:8,protocol:"TCP",dns:[
			{name:"us2-tcp.ptoserver.com",port_number:80},
			{name:"us2-alt.ptoserver.com",port_number:8080}
		]},
		{number:9,protocol:"UDP",dns:[
			{name:"us2-udp.ptoserver.com",port_number:15021},
			{name:"us2-obf-udp.ptoserver.com",port_number:1210}
		]}
	]}]}};`)

	hts, err := parseLocalData(content)
	require.NoError(t, err)

	serverTCP := hts["us2-tcp.ptoserver.com"]
	assert.True(t, serverTCP.TCP)
	assert.False(t, serverTCP.UDP)
	assert.Equal(t, []uint16{80}, serverTCP.TCPPorts)
	assert.Nil(t, serverTCP.UDPPorts)

	serverUDP := hts["us2-udp.ptoserver.com"]
	assert.True(t, serverUDP.UDP)
	assert.False(t, serverUDP.TCP)
	assert.Equal(t, []uint16{15021}, serverUDP.UDPPorts)
	assert.Nil(t, serverUDP.TCPPorts)
}

func Test_parseLocalData_noHosts(t *testing.T) {
	t.Parallel()

	_, err := parseLocalData([]byte(`"use strict";module.exports={body:{countries:[{id:1,protocols:[{protocol:"IKEV",dns:[]}]}]}};`))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no TCP/UDP protocol blocks")
}

func Test_parseLocalDataFallbackIPs(t *testing.T) {
	t.Parallel()

	content := []byte(`"use strict";module.exports={body:{
		data_centers:[
			{id:10,ping_ip_address:"1.2.3.4"},
			{id:11,ping_ip_address:"5.6.7.8"}
		],
		countries:[{
			id:1,
			data_centers:[{id:10},{id:11}],
			protocols:[
				{protocol:"TCP",dns:[{name:"aa2-tcp.ptoserver.com",port_number:80}]},
				{protocol:"UDP",dns:[{name:"aa2-udp.ptoserver.com",port_number:15021}]}
			]
		}]
	}};`)

	hostToFallbackIPs := parseLocalDataFallbackIPs(content)
	require.NotEmpty(t, hostToFallbackIPs)

	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}, hostToFallbackIPs["aa2-tcp.ptoserver.com"])
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}, hostToFallbackIPs["aa2-udp.ptoserver.com"])
}
