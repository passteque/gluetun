package updater

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseInventoryURLTemplate(t *testing.T) {
	t.Parallel()

	content := []byte(`"use strict";
(0,_defineProperty2["default"])(S3, "BASE_URL_BPC", "https://bpc-prod-a230.s3.serverwild.com/bpc");
(0,_defineProperty2["default"])(S3, "INVENTORY_URL", "".concat(S3.BASE_URL_BPC, "/{resellerUid}/inventory/shared/linux/v3/app.json"));`)

	template, err := parseInventoryURLTemplate(content)
	require.NoError(t, err)

	assert.Equal(t,
		"https://bpc-prod-a230.s3.serverwild.com/bpc/{resellerUid}/inventory/shared/linux/v3/app.json",
		template)
}

func Test_buildInventoryURL(t *testing.T) {
	t.Parallel()

	url, err := buildInventoryURL(
		"https://bpc-prod-a230.s3.serverwild.com/bpc/{resellerUid}/inventory/shared/linux/v3/app.json",
		"res_abc")
	require.NoError(t, err)
	assert.Equal(t, "https://bpc-prod-a230.s3.serverwild.com/bpc/res_abc/inventory/shared/linux/v3/app.json", url)
}

func Test_parseInventoryJSON(t *testing.T) {
	t.Parallel()

	content := []byte(`{
		"body":{
			"data_centers":[
				{"id":10,"ip":"1.2.3.4"},
				{"id":11,"ip":"5.6.7.8"}
			],
			"dns":[
				{"id":101,"hostname":"aa2-tcp.ptoserver.com","type":"primary","configuration_version":"2.0","tags":["p2p"]},
				{"id":102,"hostname":"aa2-udp.ptoserver.com","type":"primary","configuration_version":"14.0"}
			],
			"countries":[
				{
					"features":["p2p"],
					"data_centers":[{"id":10},{"id":11}],
					"protocols":[
						{"protocol":"TCP","dns":[{"dns_id":101,"port_number":80}]},
						{"protocol":"UDP","dns":[{"dns_id":102,"port_number":15021}]}
					]
				}
			]
		}
	}`)

	hts, hostToFallbackIPs, err := parseInventoryJSON(content)
	require.NoError(t, err)

	serverTCP := hts["aa2-tcp.ptoserver.com"]
	assert.True(t, serverTCP.TCP)
	assert.False(t, serverTCP.UDP)
	assert.Equal(t, []uint16{80}, serverTCP.TCPPorts)
	assert.Nil(t, serverTCP.UDPPorts)
	assert.Equal(t, []string{"p2p"}, serverTCP.Categories)

	serverUDP := hts["aa2-udp.ptoserver.com"]
	assert.True(t, serverUDP.UDP)
	assert.False(t, serverUDP.TCP)
	assert.Equal(t, []uint16{15021}, serverUDP.UDPPorts)
	assert.Nil(t, serverUDP.TCPPorts)
	assert.Equal(t, []string{"p2p"}, serverUDP.Categories)

	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}, hostToFallbackIPs["aa2-tcp.ptoserver.com"])

	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}, hostToFallbackIPs["aa2-udp.ptoserver.com"])
}

func Test_parseInventoryConfigurationVersions(t *testing.T) {
	t.Parallel()

	content := []byte(`{
		"body":{
			"dns":[
				{"id":101,"hostname":"aa2-tcp.ptoserver.com","configuration_version":"2.0"},
				{"id":102,"hostname":"aa2-udp.ptoserver.com","configuration_version":"14.0"},
				{"id":103,"hostname":"aa3-udp.ptoserver.com","configuration_version":"14.0"},
				{"id":104,"hostname":"aa4-udp.ptoserver.com","configuration_version":""}
			]
		}
	}`)

	versions, err := parseInventoryConfigurationVersions(content)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"2.0", "14.0"}, versions)
}

func Test_hasP2PTag(t *testing.T) {
	t.Parallel()

	assert.True(t, hasP2PTag([]string{"p2p"}))
	assert.True(t, hasP2PTag([]string{"TAG_P2P"}))
	assert.True(t, hasP2PTag([]string{"tag-p2p"}))
	assert.True(t, hasP2PTag([]string{"tag p2p"}))
	assert.False(t, hasP2PTag([]string{"TAG_QR", "TAG_OVPN_OBF"}))
}
