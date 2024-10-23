package updater

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_fetchAPI(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		responseStatus int
		responseBody   io.ReadCloser
		data           apiData
		err            error
	}{
		"http response status not ok": {
			responseStatus: http.StatusNoContent,
			err:            errors.New("HTTP response status code is not OK: 204 No Content"),
		},
		"nil body": {
			responseStatus: http.StatusOK,
			err:            errors.New("decoding response body: EOF"),
		},
		"no server": {
			responseStatus: http.StatusOK,
			responseBody:   io.NopCloser(strings.NewReader(`{}`)),
		},
		"success": {
			responseStatus: http.StatusOK,
			responseBody: io.NopCloser(strings.NewReader(`{
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
		        }
		      ]
		    }
		  ]
		}`)),
			data: apiData{
				Success: true,
				DataCenters: []apiDataCenter{
					{CountryName: "Austria", City: "Vienna", Servers: []apiServer{
						{
							IP:                    netip.MustParseAddr("37.120.212.227"),
							Ptr:                   "vpn44.prd.vienna.ovpn.com",
							Online:                true,
							PublicKey:             "r83LIc0Q2F8s3dY9x5y17Yz8wTADJc7giW1t5eSmoXc=",
							WireguardPorts:        []uint16{9929},
							MultiHopOpenvpnPort:   20044,
							MultiHopWireguardPort: 30044,
						},
					}},
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
						Body:       testCase.responseBody,
					}, nil
				}),
			}

			data, err := fetchAPI(ctx, client)

			assert.Equal(t, testCase.data, data)
			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
