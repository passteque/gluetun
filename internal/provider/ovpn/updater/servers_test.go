package updater

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
)

func Test_Updater_FetchServers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// Inputs
		minServers int

		// From API
		responseStatus int
		responseBody   string

		// Output
		servers    []models.Server
		errWrapped error
		errMessage string
	}{
		"http_response_error": {
			responseStatus: http.StatusNoContent,
			errMessage:     "fetching API: HTTP response status code is not OK: 204 No Content",
		},
		"success_field_false": {
			responseStatus: http.StatusOK,
			responseBody:   `{"success": false}`,
			errMessage:     "response success field is false",
		},
		"validation_failed": {
			responseStatus: http.StatusOK,
			responseBody: `{
  "success": true,
  "datacenters": [
    {
      "city": "Vienna",
      "servers": [
        {}
      ]
    }
  ]
}`,
			errMessage: "validating data center 1 of 1: data center Vienna: country name is not set",
		},
		"not_enough_servers": {
			minServers:     5,
			responseStatus: http.StatusOK,
			responseBody: `{
  "success": true,
  "datacenters": [
    {
      "city": "Vienna",
      "country_name": "Austria",
      "servers": [
        {
          "ip": "37.120.212.227",
          "ptr": "vpn44.prd.vienna.ovpn.com",
          "online": true,
          "public_key": "r83LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
          "wireguard_ports": [9929],
          "multihop_openvpn_port": 20044,
          "multihop_wireguard_port": 30044
        }
      ]
    }
  ]
}`,
			errWrapped: common.ErrNotEnoughServers,
			errMessage: "not enough servers found: 4 and expected at least 5",
		},
		"success": {
			minServers: 4,
			responseBody: `{
  "success": true,
  "datacenters": [
    {
      "slug": "vienna",
      "city": "Vienna",
      "country": "AT",
      "country_name": "Austria",
      "pools": [
        "pool-1.prd.at.vienna.ovpn.com"
      ],
      "ping_address": "37.120.212.227",
      "servers": [
        {
          "ip": "37.120.212.227",
          "ptr": "vpn44.prd.vienna.ovpn.com",
          "name": "VPN44 - Vienna",
          "online": true,
          "load": 8,
          "public_key": "r83LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
          "public_key_ipv4": "wFbSRyjSXBmkjJodlqz7DoYn3WNDPYFUIXyIUS2QU2A=",
          "wireguard_ports": [
            9929
          ],
          "multihop_openvpn_port": 20044,
          "multihop_wireguard_port": 30044
        },
        {
          "ip": "37.120.212.228",
          "ptr": "vpn45.prd.vienna.ovpn.com",
          "online": false,
          "public_key": "r93LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
          "wireguard_ports": [9929],
          "multihop_openvpn_port": 20045,
          "multihop_wireguard_port": 30045
        }
      ]
    }
  ]
}`,
			responseStatus: http.StatusOK,
			servers: []models.Server{
				{
					Country:  "Austria",
					City:     "Vienna",
					Hostname: "vpn44.prd.vienna.ovpn.com",
					IPs:      []netip.Addr{netip.MustParseAddr("37.120.212.227")},
					VPN:      vpn.OpenVPN,
					UDP:      true,
					TCP:      true,
				},
				{
					Country:  "Austria",
					City:     "Vienna",
					Hostname: "vpn44.prd.vienna.ovpn.com",
					IPs:      []netip.Addr{netip.MustParseAddr("37.120.212.227")},
					VPN:      vpn.OpenVPN,
					UDP:      true,
					TCP:      true,
					MultiHop: true,
					PortsTCP: []uint16{20044},
					PortsUDP: []uint16{20044},
				},
				{
					Country:  "Austria",
					City:     "Vienna",
					Hostname: "vpn44.prd.vienna.ovpn.com",
					IPs:      []netip.Addr{netip.MustParseAddr("37.120.212.227")},
					VPN:      vpn.Wireguard,
					WgPubKey: "r83LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
				},
				{
					Country:  "Austria",
					City:     "Vienna",
					Hostname: "vpn44.prd.vienna.ovpn.com",
					IPs:      []netip.Addr{netip.MustParseAddr("37.120.212.227")},
					VPN:      vpn.Wireguard,
					WgPubKey: "r83LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
					MultiHop: true,
					PortsUDP: []uint16{30044},
				},
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, http.MethodGet, r.Method)
					assert.Equal(t, r.URL.String(), "https://www.ovpn.com/v2/api/client/entry")
					return &http.Response{
						StatusCode: testCase.responseStatus,
						Status:     http.StatusText(testCase.responseStatus),
						Body:       io.NopCloser(strings.NewReader(testCase.responseBody)),
					}, nil
				}),
			}

			updater := &Updater{
				client: client,
			}

			servers, err := updater.FetchServers(ctx, testCase.minServers)

			assert.Equal(t, testCase.servers, servers)
			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), testCase.errMessage)
			}
			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
		})
	}
}
