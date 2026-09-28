package privateinternetaccess

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Provider_GetConnection(t *testing.T) {
	t.Parallel()

	const provider = providers.PrivateInternetAccess

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
			selection: settings.ServerSelection{}.WithDefaults(provider),
			errMessage: "filtering servers: test error",
		},
		"default OpenVPN TCP port": {
			filteredServers: []models.Server{
				{
					ServerName: "bahamas413",
					Hostname:   "bahamas.privacy.network",
					IPs:        []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
				},
			},
			selection: settings.ServerSelection{
				OpenVPN: settings.OpenVPNSelection{
					Protocol: constants.TCP,
				},
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:       vpn.OpenVPN,
				IP:         netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:       8443,
				Protocol:   constants.TCP,
				ServerName: "bahamas413",
				Hostname:   "bahamas.privacy.network",
			},
		},
		"default OpenVPN UDP port": {
			filteredServers: []models.Server{
				{
					ServerName: "bahamas413",
					Hostname:   "bahamas.privacy.network",
					IPs:        []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
				},
			},
			selection: settings.ServerSelection{
				OpenVPN: settings.OpenVPNSelection{
					Protocol: constants.UDP,
				},
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:       vpn.OpenVPN,
				IP:         netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:       8080,
				Protocol:   constants.UDP,
				ServerName: "bahamas413",
				Hostname:   "bahamas.privacy.network",
			},
		},
		"default Wireguard port": {
			filteredServers: []models.Server{
				{
					ServerName: "bahamas413",
					Hostname:   "bahamas.privacy.network",
					IPs:        []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})},
				},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:       vpn.Wireguard,
				IP:         netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:       1337,
				Protocol:   constants.UDP,
				ServerName: "bahamas413",
				Hostname:   "bahamas.privacy.network",
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

			timeNow := time.Now
			client := (*http.Client)(nil)
			provider := New(storage, timeNow, client)

			connection, err := provider.GetConnection(testCase.selection, testCase.ipv6Supported)

			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.Equal(t, testCase.errMessage, err.Error())
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.connection, connection)
		})
	}
}
