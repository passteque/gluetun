package ovpn

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

	const provider = providers.Ovpn

	errTest := errors.New("test error")

	testCases := map[string]struct {
		filteredServers []models.Server
		storageErr      error
		selection       settings.ServerSelection
		ipv6Supported   bool
		connection      models.Connection
		errWrapped      error
		errMessage      string
	}{
		"error": {
			storageErr: errTest,
			errWrapped: errTest,
			errMessage: "filtering servers: test error",
		},
		"default_openvpn_tcp_port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}},
			},
			selection: settings.ServerSelection{
				OpenVPN: settings.OpenVPNSelection{
					Protocol: constants.TCP,
				},
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:     vpn.OpenVPN,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:     443,
				Protocol: constants.TCP,
			},
		},
		"default_openvpn_udp_port": {
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
				Port:     1194,
				Protocol: constants.UDP,
			},
		},
		"default_wireguard_port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}, WgPubKey: "x"},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:     9929,
				Protocol: constants.UDP,
				PubKey:   "x",
			},
		},
		"default_multihop_port": {
			filteredServers: []models.Server{
				{IPs: []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}, WgPubKey: "x", PortsUDP: []uint16{30044}},
			},
			selection: settings.ServerSelection{
				VPN: vpn.Wireguard,
			}.WithDefaults(provider),
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				Port:     30044,
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

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}

			assert.Equal(t, testCase.connection, connection)
		})
	}
}
