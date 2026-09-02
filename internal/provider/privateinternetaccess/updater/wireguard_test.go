package updater

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Updater_FetchWireguardServers(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodGet, request.Method)
			assert.Equal(t, "https://serverlist.piaservers.net/vpninfo/servers/v6", request.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body: io.NopCloser(strings.NewReader(
					`{"regions":[{"id":"ca_vancouver","name":"CA Vancouver",` +
						`"dns":"ca-vancouver.privacy.network","port_forward":true,` +
						`"servers":{"wg":[{"ip":"198.51.100.2","cn":"vancouver439"}]}}]}` +
						"\nserver-list-signature")),
			}, nil
		}),
	}
	updater := New(client)
	selection := settings.ServerSelection{
		VPN:     vpn.Wireguard,
		Regions: []string{"ca vAnCoUvEr"},
	}.WithDefaults(providers.PrivateInternetAccess)

	servers, err := updater.FetchWireguardServers(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, []models.Server{{
		VPN:              vpn.Wireguard,
		Region:           "CA Vancouver",
		ServerName:       "vancouver439",
		Hostname:         "ca-vancouver.privacy.network",
		WireguardDynamic: true,
		PortForward:      true,
		IPs:              []netip.Addr{netip.MustParseAddr("198.51.100.2")},
	}}, servers)
}

func Test_selectWireguardServers(t *testing.T) {
	t.Parallel()

	vancouverRegion := regionData{
		ID:          "ca_vancouver",
		Name:        "CA Vancouver",
		DNS:         "ca-vancouver.privacy.network",
		PortForward: true,
	}
	vancouverRegion.Servers.WG = []serverData{
		{IP: netip.MustParseAddr("198.51.100.2"), CN: "vancouver439"},
		{IP: netip.MustParseAddr("198.51.100.3"), CN: "vancouver440"},
	}
	londonRegion := regionData{
		ID:   "uk_london",
		Name: "UK London",
		DNS:  "uk-london.privacy.network",
	}
	londonRegion.Servers.WG = []serverData{{
		IP: netip.MustParseAddr("203.0.113.2"), CN: "london401",
	}}
	regions := []regionData{vancouverRegion, londonRegion}

	testCases := map[string]struct {
		selection       settings.ServerSelection
		portForwardOnly bool
		expectedServers []string
		errMessage      string
	}{
		"region_name_case_insensitive": {
			selection:       settings.ServerSelection{Regions: []string{"ca vAnCoUvEr"}},
			expectedServers: []string{"vancouver439", "vancouver440"},
		},
		"region_id": {
			selection:       settings.ServerSelection{Regions: []string{"CA_VANCOUVER"}},
			expectedServers: []string{"vancouver439", "vancouver440"},
		},
		"server_name": {
			selection:       settings.ServerSelection{Names: []string{"VANCOUVER440"}},
			expectedServers: []string{"vancouver440"},
		},
		"hostname_only": {
			selection: settings.ServerSelection{
				Hostnames: []string{"UK-LONDON.PRIVACY.NETWORK"},
			},
			expectedServers: []string{"london401"},
		},
		"combined_region_name_and_hostname": {
			selection: settings.ServerSelection{
				Regions:   []string{"ca_vancouver"},
				Names:     []string{"vancouver440"},
				Hostnames: []string{"ca-vancouver.privacy.network"},
			},
			expectedServers: []string{"vancouver440"},
		},
		"hostname_no_match": {
			selection: settings.ServerSelection{
				Hostnames: []string{"sydney.privacy.network"},
			},
			errMessage: "no Wireguard server found matching selection",
		},
		"combined_filters_must_all_match": {
			selection: settings.ServerSelection{
				Regions:   []string{"ca_vancouver"},
				Hostnames: []string{"uk-london.privacy.network"},
			},
			errMessage: "no Wireguard server found matching selection",
		},
		"region_id_as_server_name": {
			selection:       settings.ServerSelection{Names: []string{"ca_vancouver"}},
			expectedServers: []string{"vancouver439", "vancouver440"},
		},
		"port_forwarding_only": {
			selection:       settings.ServerSelection{Regions: []string{"UK London"}},
			portForwardOnly: true,
			errMessage:      "no Wireguard server found matching selection",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := testCase.selection.WithDefaults(providers.PrivateInternetAccess)
			if testCase.portForwardOnly {
				*selection.PortForwardOnly = true
			}
			servers, err := selectWireguardServers(regions, selection)
			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}

			require.NoError(t, err)
			serverNames := make([]string, len(servers))
			for i, server := range servers {
				serverNames[i] = server.ServerName
			}
			assert.Equal(t, testCase.expectedServers, serverNames)
		})
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
