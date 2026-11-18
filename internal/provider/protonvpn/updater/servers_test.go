package updater

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
)

func Test_Updater_serversFromData(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// Inputs
		data       apiData
		minServers int

		// Outputs
		servers    []models.Server
		errWrapped error
		errMessage string
	}{
		"no_minimum": {
			data: apiData{LogicalServers: []logicalServer{{
				Name: "US#81", ExitCountry: "US", Tier: ptrTo(uint8(2)),
				Servers: []physicalServer{{
					Status: 1, Domain: "example.org",
					EntryIP: netip.MustParseAddr("1.2.3.4"), X25519PublicKey: "pubkey",
				}},
			}}},
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
				{
					VPN:        vpn.Wireguard,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					WgPubKey:   "pubkey",
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
			},
		},
		"physical_count": {
			data: apiData{LogicalServers: []logicalServer{{
				Name: "US#81", ExitCountry: "US", Tier: ptrTo(uint8(2)),
				Servers: []physicalServer{{
					Status: 1, Domain: "example.org",
					EntryIP: netip.MustParseAddr("1.2.3.4"), X25519PublicKey: "pubkey",
				}},
			}}},
			minServers: 1,
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
				{
					VPN:        vpn.Wireguard,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					WgPubKey:   "pubkey",
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
			},
		},
		"protocol_count": {
			data: apiData{LogicalServers: []logicalServer{{
				Name: "US#81", ExitCountry: "US", Tier: ptrTo(uint8(2)),
				Servers: []physicalServer{{
					Status: 1, Domain: "example.org",
					EntryIP: netip.MustParseAddr("1.2.3.4"), X25519PublicKey: "pubkey",
				}},
			}}},
			minServers: 2,
			servers: []models.Server{
				{
					VPN:        vpn.OpenVPN,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					TCP:        true,
					UDP:        true,
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
				{
					VPN:        vpn.Wireguard,
					Country:    "United States",
					ServerName: "US#81",
					Hostname:   "example.org",
					WgPubKey:   "pubkey",
					IPs:        []netip.Addr{netip.MustParseAddr("1.2.3.4")},
				},
			},
		},
		"below_minimum": {
			data: apiData{LogicalServers: []logicalServer{{
				Name: "US#81", ExitCountry: "US", Tier: ptrTo(uint8(2)),
				Servers: []physicalServer{{
					Status: 1, Domain: "example.org",
					EntryIP: netip.MustParseAddr("1.2.3.4"), X25519PublicKey: "pubkey",
				}},
			}}},
			minServers: 3,
			errWrapped: common.ErrNotEnoughServers,
			errMessage: "not enough servers found: 2 and expected at least 3",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			updater := &Updater{}

			servers, err := updater.serversFromData(testCase.data, testCase.minServers)

			assert.Equal(t, testCase.servers, servers)
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ptrTo returns a pointer to the value given. Written here because the go
// directive of this branch is 1.25, which does not allow new with a value.
func ptrTo[T any](value T) *T {
	return &value
}
