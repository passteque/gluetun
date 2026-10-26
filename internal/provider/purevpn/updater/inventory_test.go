package updater

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseInventoryURLTemplate(t *testing.T) {
	t.Parallel()

	content := []byte(`"use strict";
(0,_defineProperty2["default"])(S3, "BASE_URL_BPC", "https://bpc-prod-a230.s3.serverwild.com/bpc");
(0,_defineProperty2["default"])(S3, "INVENTORY_URL", ` +
		`"".concat(S3.BASE_URL_BPC, "/{resellerUid}/inventory/shared/linux/v3/app.json"));`)

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

	const content = `{
		"body":{
			"data_centers":[
				{"id":10,"ip":"1.2.3.4"},
				{"id":11,"ip":"5.6.7.8"}
			],
			"dns":[
				{"id":101,"hostname":"aa2-tcp.ptoserver.com","type":"primary"},
				{"id":102,"hostname":"aa2-udp.ptoserver.com","type":"primary"},
				{"id":103,"hostname":"aa2-obf-udp.ptoserver.com","type":"primary"}
			],
			"countries":[
				{
					"features":["p2p"],
					"data_centers":[{"id":10},{"id":11}],
					"protocols":[
						{"protocol":"TCP","dns":[{"dns_id":101,"port_number":80}]},
						{"protocol":"UDP","dns":[{"dns_id":102,"port_number":15021}]},
						{"protocol":"UDP","dns":[{"dns_id":103,"port_number":5565}]},
						{"protocol":"IKEV","dns":[{"dns_id":101,"port_number":0}]}
					]
				}
			]
		}
	}`

	hts, err := parseInventoryJSON(bytes.NewBufferString(content))
	require.NoError(t, err)

	serverTCP := hts["aa2-tcp.ptoserver.com"]
	expectedServerTCP := models.Server{
		Hostname:   "aa2-tcp.ptoserver.com",
		VPN:        vpn.OpenVPN,
		TCP:        true,
		UDP:        false,
		TCPPorts:   []uint16{80},
		Categories: []string{"p2p"},
		IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
	}
	assert.Equal(t, expectedServerTCP, serverTCP)

	serverUDP := hts["aa2-udp.ptoserver.com"]
	expectedServerUDP := models.Server{
		Hostname:   "aa2-udp.ptoserver.com",
		VPN:        vpn.OpenVPN,
		TCP:        false,
		UDP:        true,
		UDPPorts:   []uint16{15021},
		Categories: []string{"p2p"},
		IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
	}
	assert.Equal(t, expectedServerUDP, serverUDP)

	serverObfuscated := hts["aa2-obf-udp.ptoserver.com"]
	expectedServerObfuscated := models.Server{
		Hostname:   "aa2-obf-udp.ptoserver.com",
		VPN:        vpn.OpenVPN,
		UDP:        true,
		UDPPorts:   []uint16{5565},
		Obfuscated: true,
		Categories: []string{"p2p"},
		IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
	}
	assert.Equal(t, expectedServerObfuscated, serverObfuscated)
}

func Test_hasP2PFeature(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		features []string
		hasP2P   bool
	}{
		"none": {
			features: nil,
		},
		"other_features": {
			features: []string{"QR", "OVPN_OBF", "PF"},
		},
		"p2p": {
			features: []string{"p2p"},
			hasP2P:   true,
		},
		"p2p_with_other_features": {
			features: []string{"QR", "p2p", "PF"},
			hasP2P:   true,
		},
		"p2p_in_uppercase": {
			features: []string{"P2P"},
			hasP2P:   true,
		},
		"p2p_with_spaces": {
			features: []string{" p2p "},
			hasP2P:   true,
		},
		"p2p_as_a_substring": {
			features: []string{"tag_p2p"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hasP2P := hasP2PFeature(testCase.features)

			assert.Equal(t, testCase.hasP2P, hasP2P)
		})
	}
}

// Test_parseInventoryJSON_cities tests the city of each server is taken from
// the cities of the inventory, which reference servers by their DNS entry ID.
func Test_parseInventoryJSON_cities(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content         string
		expectedServers map[string]models.Server
	}{
		"city_only_servers_and_merges": {
			content: `{
				"body":{
					"data_centers":[
						{"id":10,"ip":"1.2.3.4"},
						{"id":11,"ip":"5.6.7.8"}
					],
					"dns":[
						{"id":101,"hostname":"aa2-tcp.ptoserver.com"},
						{"id":102,"hostname":"aa2-udp.ptoserver.com"},
						{"id":104,"hostname":"cityonly2-udp.ptoserver.com"},
						{"id":105,"hostname":"empty2-udp.ptoserver.com"}
					],
					"countries":[
						{
							"data_centers":[{"id":10},{"id":11},{"id":10}],
							"protocols":[
								{"protocol":"TCP","dns":[{"dns_id":101,"port_number":80}]},
								{"protocol":"UDP","dns":[{"dns_id":102,"port_number":15021}]}
							]
						}
					],
					"cities":[
						{
							"name":"Metro",
							"data_centers":[{"id":10},{"id":11},{"id":10}],
							"features":["p2p"],
							"protocols":[
								{"protocol":"UDP","dns":[
									{"dns_id":104,"port_number":5565},
									{"dns_id":104,"port_number":5565}
								]}
							]
						},
						{
							"name":"First City",
							"data_centers":[{"id":10},{"id":11}],
							"protocols":[
								{"protocol":"TCP","dns":[{"dns_id":101,"port_number":80}]},
								{"protocol":"UDP","dns":[{"dns_id":102,"port_number":5565}]}
							]
						},
						{
							"name":"Second City",
							"data_centers":[{"id":11}],
							"protocols":[
								{"protocol":"UDP","dns":[{"dns_id":102,"port_number":5565}]}
							]
						},
						{
							"name":"",
							"data_centers":[{"id":10}],
							"protocols":[
								{"protocol":"UDP","dns":[{"dns_id":105,"port_number":5565}]}
							]
						}
					]
				}
			}`,
			expectedServers: map[string]models.Server{
				"aa2-tcp.ptoserver.com": {
					Hostname: "aa2-tcp.ptoserver.com",
					VPN:      vpn.OpenVPN,
					TCP:      true,
					TCPPorts: []uint16{80},
					City:     "First City",
					IPs:      []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
				},
				"aa2-udp.ptoserver.com": {
					Hostname: "aa2-udp.ptoserver.com",
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{15021, 5565},
					City:     "First City",
					IPs:      []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
				},
				"cityonly2-udp.ptoserver.com": {
					Hostname:   "cityonly2-udp.ptoserver.com",
					VPN:        vpn.OpenVPN,
					UDP:        true,
					UDPPorts:   []uint16{5565},
					Categories: []string{"p2p"},
					City:       "Metro",
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
				},
				"empty2-udp.ptoserver.com": {
					Hostname: "empty2-udp.ptoserver.com",
					VPN:      vpn.OpenVPN,
					UDP:      true,
					UDPPorts: []uint16{5565},
					IPs:      []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hts, err := parseInventoryJSON(bytes.NewBufferString(testCase.content))
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedServers, map[string]models.Server(hts))
		})
	}
}
