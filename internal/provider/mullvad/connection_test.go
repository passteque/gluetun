package mullvad

import (
	"errors"
	"net/http"
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

	const provider = providers.Mullvad

	testCases := map[string]struct {
		filteredServers []models.Server
		storageErr      error
		selection       settings.ServerSelection
		ipv6Supported   bool
		connection      models.Connection
		errMessage      string
	}{
		"error": {
			storageErr: errors.New("test error"),
			errMessage: "filtering servers: test error",
		},
		"default Wireguard port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}, WgPubKey: "x"},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:     51820,
				Protocol: constants.UDP,
				PubKey:   "x",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := common.NewMockStorage(ctrl)
			storage.EXPECT().FilterServers(provider, testCase.selection).
				Return(testCase.filteredServers, testCase.storageErr)

			client := (*http.Client)(nil)
			provider := New(storage, client)

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
