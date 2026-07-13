package privateinternetaccess

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Provider_GetWireguardConnection(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: piaRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body: io.NopCloser(strings.NewReader(
					`{"regions":[{"id":"ca_vancouver","name":"CA Vancouver",` +
						`"dns":"ca-vancouver.privacy.network","port_forward":true,` +
						`"servers":{"wg":[{"ip":"198.51.100.2","cn":"vancouver439"}]}}]}` +
						"\nsignature")),
			}, nil
		}),
	}
	provider := New(nil, time.Now, client)
	const serverListIPString = "192.0.2.10"
	serverListIP := netip.MustParseAddr(serverListIPString)
	lookupNetIP := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		assert.Equal(t, "ip4", network)
		assert.Equal(t, "serverlist.piaservers.net", host)
		return []netip.Addr{serverListIP}, nil
	}
	provider.newDialingClient = func(serverName string, serverIP netip.Addr,
		_ func(context.Context, string, string) (net.Conn, error),
	) (*http.Client, error) {
		assert.Equal(t, "serverlist.piaservers.net", serverName)
		assert.Equal(t, serverListIP, serverIP)
		return client, nil
	}
	selection := settings.ServerSelection{
		VPN:     vpn.Wireguard,
		Regions: []string{"ca_vancouver"},
	}.WithDefaults(providers.PrivateInternetAccess)

	var allowedConnection models.Connection
	connectionAllowanceRemoved := false
	allowConnection := func(_ context.Context, connection models.Connection) (
		func(context.Context) error, error,
	) {
		allowedConnection = connection
		return func(context.Context) error {
			connectionAllowanceRemoved = true
			return nil
		}, nil
	}
	connection, err := provider.GetWireguardConnection(context.Background(), selection,
		lookupNetIP, new(net.Dialer).DialContext, allowConnection)
	require.NoError(t, err)
	assert.Equal(t, models.Connection{
		IP:       serverListIP,
		Port:     443,
		Protocol: constants.TCP,
	}, allowedConnection)
	assert.Equal(t, models.Connection{
		Type:        vpn.Wireguard,
		IP:          netip.MustParseAddr("198.51.100.2"),
		Port:        wireguardRegistrationPort,
		Protocol:    constants.UDP,
		Hostname:    "ca-vancouver.privacy.network",
		ServerName:  "vancouver439",
		PortForward: true,
	}, connection)
	assert.True(t, connectionAllowanceRemoved)
}

func Test_Provider_GetConnection_wireguard(t *testing.T) {
	t.Parallel()

	selection := settings.ServerSelection{VPN: vpn.Wireguard}.
		WithDefaults(providers.PrivateInternetAccess)
	server := models.Server{
		VPN:              vpn.Wireguard,
		Region:           "CA Vancouver",
		ServerName:       testPIAServerName,
		Hostname:         "ca-vancouver.privacy.network",
		PortForward:      true,
		WireguardDynamic: true,
		IPs:               []netip.Addr{netip.MustParseAddr("198.51.100.2")},
	}
	controller := gomock.NewController(t)
	storage := common.NewMockStorage(controller)
	storage.EXPECT().FilterServers(providers.PrivateInternetAccess, selection).
		Return([]models.Server{server}, nil)
	provider := New(storage, time.Now, nil)

	connection, err := provider.GetConnection(selection, false)
	require.NoError(t, err)

	const registrationPort uint16 = 1337
	assert.Equal(t, registrationPort, connection.Port)
	assert.Equal(t, server.IPs[0], connection.IP)
	assert.Equal(t, server.ServerName, connection.ServerName)
	assert.True(t, connection.PortForward)
}

type piaRoundTripFunc func(request *http.Request) (*http.Response, error)

func (f piaRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
