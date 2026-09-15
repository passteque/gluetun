package updater

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_addData(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		regions  []regionData
		initial  nameToServer
		expected nameToServer
		change   bool
	}{
		"empty regions": {
			regions:  nil,
			initial:  make(nameToServer),
			expected: make(nameToServer),
			change:   false,
		},
		"offline region": {
			regions: []regionData{
				{
					Name:    "Bahamas",
					Offline: true,
					Servers: struct {
						UDP []serverData `json:"ovpnudp"`
						TCP []serverData `json:"ovpntcp"`
						WG  []serverData `json:"wg"`
					}{
						WG: []serverData{
							{CN: "bahamas413", IP: netip.AddrFrom4([4]byte{95, 181, 238, 98})},
						},
					},
				},
			},
			initial:  make(nameToServer),
			expected: make(nameToServer),
			change:   false,
		},
		"openvpn and wireguard servers": {
			regions: []regionData{
				{
					Name:        "Bahamas",
					DNS:         "bahamas.privacy.network",
					PortForward: true,
					Offline:     false,
					Servers: struct {
						UDP []serverData `json:"ovpnudp"`
						TCP []serverData `json:"ovpntcp"`
						WG  []serverData `json:"wg"`
					}{
						UDP: []serverData{
							{CN: "bahamas413", IP: netip.AddrFrom4([4]byte{95, 181, 238, 89})},
						},
						TCP: []serverData{
							{CN: "bahamas413", IP: netip.AddrFrom4([4]byte{95, 181, 238, 106})},
						},
						WG: []serverData{
							{CN: "bahamas413", IP: netip.AddrFrom4([4]byte{95, 181, 238, 98})},
						},
					},
				},
			},
			initial: make(nameToServer),
			expected: nameToServer{
				"openvpn-bahamas413": models.Server{
					VPN:         vpn.OpenVPN,
					ServerName:  "bahamas413",
					Hostname:    "bahamas.privacy.network",
					Region:      "Bahamas",
					PortForward: true,
					UDP:         true,
					TCP:         true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{95, 181, 238, 89}),
						netip.AddrFrom4([4]byte{95, 181, 238, 106}),
					},
				},
				"wireguard-bahamas413": models.Server{
					VPN:         vpn.Wireguard,
					ServerName:  "bahamas413",
					Hostname:    "bahamas.privacy.network",
					Region:      "Bahamas",
					PortForward: true,
					IPs: []netip.Addr{
						netip.AddrFrom4([4]byte{95, 181, 238, 98}),
					},
				},
			},
			change: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nts := make(nameToServer)
			for k, v := range testCase.initial {
				nts[k] = v
			}

			change := addData(testCase.regions, nts)

			assert.Equal(t, testCase.change, change)
			assert.Equal(t, testCase.expected, nts)
		})
	}
}
