package expressvpn

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
)

func Test_Provider_GetConnection(t *testing.T) {
	t.Parallel()

	const provider = providers.Expressvpn

	testCases := map[string]struct {
		filteredServers []models.Server
		storageErr      error
		selection       settings.ServerSelection
		ipv6Supported   bool
		connection      models.Connection
		errMessage      string
		panicMessage    string
	}{
		"error": {
			storageErr: errors.New("test error"),
			errMessage: "filtering servers: test error",
		},
		"default OpenVPN TCP port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}},
			},
			selection: settings.ServerSelection{
				OpenVPN: settings.OpenVPNSelection{
					Protocol: constants.TCP,
				},
			}.WithDefaults(provider),
			panicMessage: "no default OpenVPN TCP port is defined!",
		},
		"default OpenVPN UDP port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}},
			},
			selection: settings.ServerSelection{
				OpenVPN: settings.OpenVPNSelection{
					Protocol: constants.UDP,
				},
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:     1195,
				Protocol: constants.UDP,
			},
		},
		"default Wireguard port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(provider),
			panicMessage: "no default Wireguard port is defined!",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := common.NewMockStorage(ctrl)
			storage.EXPECT().FilterServers(provider, testCase.selection).
				Return(testCase.filteredServers, testCase.storageErr)

			unzipper := (common.Unzipper)(nil)
			warner := (common.Warner)(nil)
			parallelResolver := (common.ParallelResolver)(nil)
			provider := New(storage, unzipper, warner, parallelResolver)

			if testCase.panicMessage != "" {
				assert.PanicsWithValue(t, testCase.panicMessage, func() {
					_, _ = provider.GetConnection(testCase.selection, testCase.ipv6Supported)
				})
				return
			}

			connection, err := provider.GetConnection(testCase.selection, testCase.ipv6Supported)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.connection, connection)
		})
	}
}
