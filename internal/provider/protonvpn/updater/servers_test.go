package updater

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Updater_serversFromData(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		minServers int
		notEnough  bool
	}{
		"no_minimum":     {},
		"physical_count": {minServers: 1},
		"protocol_count": {minServers: 2},
		"below_minimum":  {minServers: 3, notEnough: true},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tier := uint8(2)
			data := apiData{LogicalServers: []logicalServer{{
				Name: "US#81", ExitCountry: "US", Tier: &tier,
				Servers: []physicalServer{{
					Status: 1, Domain: "example.org",
					EntryIP: netip.MustParseAddr("1.2.3.4"), X25519PublicKey: "pubkey",
				}},
			}}}
			updater := &Updater{}
			servers, err := updater.serversFromData(data, testCase.minServers)
			if testCase.notEnough {
				assert.ErrorIs(t, err, common.ErrNotEnoughServers)
				assert.ErrorContains(t, err, "2 and expected at least 3")
				assert.Nil(t, servers)
				return
			}
			require.NoError(t, err)
			require.Len(t, servers, 2)
			assert.ElementsMatch(t, []string{vpn.OpenVPN, vpn.Wireguard}, []string{servers[0].VPN, servers[1].VPN})
		})
	}
}
