package privateinternetaccess

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/netip"
	"strings"
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
						`"servers":{"wg":[{"ip":"198.51.100.2","cn":"vancouver439"},` +
						`{"ip":"198.51.100.4","cn":"vancouver440"}]}}]}` +
						"\nsignature")),
			}, nil
		}),
	}
	cleanupCalls := 0
	restrictedClient := &testRestrictedClient{
		openHTTPSByHostname: func(_ context.Context, hostname string) (*http.Client, func() error, error) {
			assert.Equal(t, "serverlist.piaservers.net:443", hostname)
			return client, func() error {
				cleanupCalls++
				return nil
			}, nil
		},
	}
	provider := New(nil, time.Now, client)
	selection := settings.ServerSelection{
		VPN:     vpn.Wireguard,
		Regions: []string{"ca_vancouver"},
	}.WithDefaults(providers.PrivateInternetAccess)

	connection, err := provider.GetWireguardConnection(t.Context(), selection, restrictedClient)
	require.NoError(t, err)
	assert.Equal(t, models.Connection{
		Type:        vpn.Wireguard,
		IP:          netip.MustParseAddr("198.51.100.2"),
		Port:        wireguardRegistrationPort,
		Protocol:    constants.UDP,
		Hostname:    "ca-vancouver.privacy.network",
		ServerName:  "vancouver439",
		PortForward: true,
	}, connection)

	connection, err = provider.GetWireguardConnection(t.Context(), selection, restrictedClient)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("198.51.100.4"), connection.IP)
	assert.Equal(t, "vancouver440", connection.ServerName)
	assert.Equal(t, 2, cleanupCalls)
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
		IPs:              []netip.Addr{netip.MustParseAddr("198.51.100.2")},
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

type testRestrictedClient struct {
	openHTTPSByHostname  func(context.Context, string) (*http.Client, func() error, error)
	openHTTPSWithRootCAs func(context.Context, string, netip.AddrPort,
		*x509.CertPool) (*http.Client, func() error, error)
}

func (c *testRestrictedClient) OpenHTTPSByHostname(ctx context.Context, hostname string) (
	*http.Client, func() error, error,
) {
	return c.openHTTPSByHostname(ctx, hostname)
}

func (c *testRestrictedClient) OpenHTTPSWithRootCAs(ctx context.Context, destinationTLSName string,
	destinationAddrPort netip.AddrPort, rootCAs *x509.CertPool,
) (*http.Client, func() error, error) {
	return c.openHTTPSWithRootCAs(ctx, destinationTLSName, destinationAddrPort, rootCAs)
}
