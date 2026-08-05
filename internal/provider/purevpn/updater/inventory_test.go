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
}

func Test_hasP2PTag(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tags     []string
		expected bool
	}{
		"empty": {
			tags:     nil,
			expected: false,
		},
		"no_p2p_tag": {
			tags:     []string{"TAG_QR", "TAG_OVPN_OBF"},
			expected: false,
		},
		"p2p_tag": {
			tags:     []string{"p2p"},
			expected: true,
		},
		"p2p_tag_with_different_case": {
			tags:     []string{"TAG_P2P"},
			expected: true,
		},
		"p2p_tag_with_dash": {
			tags:     []string{"tag-p2p"},
			expected: true,
		},
		"p2p_tag_with_space": {
			tags:     []string{"tag p2p"},
			expected: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := hasP2PTag(testCase.tags)

			assert.Equal(t, testCase.expected, result)
		})
	}
}
