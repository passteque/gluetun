package storage

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Storage_FilterServers verifies that a dedicated IP server is only
// selected when it is explicitly asked for, since it rejects the service
// credentials of the accounts not owning it.
func Test_Storage_FilterServers(t *testing.T) {
	t.Parallel()

	ipA := netip.MustParseAddr("5.6.7.8")
	ipB := netip.MustParseAddr("9.10.11.12")
	ipC := netip.MustParseAddr("13.14.15.16")

	standard := models.Server{
		VPN:        vpn.OpenVPN,
		Country:    "Canada",
		Hostname:   "ca1937.nordvpn.com",
		Categories: []string{"Standard VPN servers"},
		UDP:        true,
		IPs:        []netip.Addr{ipA},
	}
	dedicatedA := models.Server{
		VPN:        vpn.OpenVPN,
		Country:    "Canada",
		Hostname:   "ca1700.nordvpn.com",
		Categories: []string{"Dedicated IP"},
		Dedicated:  true,
		UDP:        true,
		IPs:        []netip.Addr{ipB},
	}
	dedicatedB := models.Server{
		VPN:        vpn.OpenVPN,
		Country:    "France",
		Hostname:   "fr100.nordvpn.com",
		Categories: []string{"Dedicated IP"},
		Dedicated:  true,
		UDP:        true,
		IPs:        []netip.Addr{ipC},
	}

	unsetOnly := new(false)
	baseSelection := settings.ServerSelection{
		VPN:  vpn.OpenVPN,
		Mode: "random",
		OpenVPN: settings.OpenVPNSelection{
			Protocol:     constants.UDP,
			PIAEncPreset: new(""),
		},
		OwnedOnly:       unsetOnly,
		FreeOnly:        unsetOnly,
		PremiumOnly:     unsetOnly,
		StreamOnly:      unsetOnly,
		MultiHopOnly:    unsetOnly,
		PortForwardOnly: unsetOnly,
		SecureCoreOnly:  unsetOnly,
		TorOnly:         unsetOnly,
	}

	testCases := map[string]struct {
		servers []models.Server
		// Server selection filters applied on top of baseSelection.
		filterCategories []string
		filterCountries  []string
		filterHostnames  []string
		// Outputs
		hostnames  []string
		errMessage string
	}{
		"no_filter_drops_dedicated_servers": {
			servers:   []models.Server{standard, dedicatedA, dedicatedB},
			hostnames: []string{"ca1937.nordvpn.com"},
		},
		"category_filter_excludes_dedicated_servers": {
			servers:          []models.Server{standard, dedicatedA},
			filterCategories: []string{"Standard VPN servers"},
			hostnames:        []string{"ca1937.nordvpn.com"},
		},
		"dedicated_servers_kept_when_category_selected": {
			servers:          []models.Server{standard, dedicatedA, dedicatedB},
			filterCategories: []string{"Dedicated IP"},
			hostnames:        []string{"ca1700.nordvpn.com", "fr100.nordvpn.com"},
		},
		"dedicated_servers_kept_when_category_and_country_selected": {
			servers:          []models.Server{standard, dedicatedA, dedicatedB},
			filterCategories: []string{"Dedicated IP"},
			filterCountries:  []string{"France"},
			hostnames:        []string{"fr100.nordvpn.com"},
		},
		"dedicated_server_kept_when_hostname_selected": {
			servers:         []models.Server{standard, dedicatedA},
			filterHostnames: []string{"ca1700.nordvpn.com"},
			hostnames:       []string{"ca1700.nordvpn.com"},
		},
		"dedicated_servers_dropped_when_no_other_server_matches": {
			servers:    []models.Server{dedicatedA, dedicatedB},
			errMessage: "no server found: for VPN openvpn; protocol udp",
		},
		"error_no_server_found": {
			servers:         []models.Server{standard},
			filterCountries: []string{"France"},
			errMessage:      "no server found: for VPN openvpn; protocol udp; country France",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			serverSelection := baseSelection
			serverSelection.Categories = testCase.filterCategories
			serverSelection.Countries = testCase.filterCountries
			serverSelection.Hostnames = testCase.filterHostnames

			storage, err := New(noopLogger{}, false, "", "")
			require.NoError(t, err)
			err = storage.SetServers(providers.Nordvpn, testCase.servers)
			require.NoError(t, err)

			servers, err := storage.FilterServers(providers.Nordvpn, serverSelection)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)

			hostnames := make([]string, len(servers))
			for i, server := range servers {
				hostnames[i] = server.Hostname
			}
			assert.Equal(t, testCase.hostnames, hostnames)
		})
	}
}
