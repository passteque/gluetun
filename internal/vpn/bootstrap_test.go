package vpn

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_bootstrapResolver_LookupNetIP(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const resolverAddress = "100.100.100.100:53"
	const host = "serverlist.piaservers.net"
	expectedAddress := netip.MustParseAddr("192.0.2.10")
	expectedConnection := models.Connection{
		IP:       netip.MustParseAddr("100.100.100.100"),
		Port:     53,
		Protocol: constants.UDP,
	}

	var allowedConnection models.Connection
	allowanceRemoved := false
	resolver := &bootstrapResolver{
		allowConnection: func(_ context.Context, connection models.Connection) (
			func(context.Context) error, error,
		) {
			allowedConnection = connection
			return func(context.Context) error {
				allowanceRemoved = true
				return nil
			}, nil
		},
		dialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			assert.Equal(t, constants.UDP, network)
			assert.Equal(t, resolverAddress, address)
			clientConnection, serverConnection := net.Pipe()
			t.Cleanup(func() {
				_ = serverConnection.Close()
			})
			return clientConnection, nil
		},
		lookupNetIP: func(lookupCtx context.Context, network, lookupHost string,
			dial func(context.Context, string, string) (net.Conn, error),
		) ([]netip.Addr, error) {
			assert.Equal(t, ctx, lookupCtx)
			assert.Equal(t, "ip4", network)
			assert.Equal(t, host, lookupHost)
			connection, err := dial(lookupCtx, constants.UDP, resolverAddress)
			require.NoError(t, err)
			require.NoError(t, connection.Close())
			assert.False(t, allowanceRemoved)
			return []netip.Addr{expectedAddress}, nil
		},
	}

	addresses, err := resolver.LookupNetIP(ctx, "ip4", host)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{expectedAddress}, addresses)
	assert.Equal(t, expectedConnection, allowedConnection)
	assert.True(t, allowanceRemoved)
}

func Test_dnsConnection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		network    string
		address    string
		connection models.Connection
		errMessage string
	}{
		"udp_ipv4": {
			network: constants.UDP + "4",
			address: "100.100.100.100:53",
			connection: models.Connection{
				IP:       netip.MustParseAddr("100.100.100.100"),
				Port:     53,
				Protocol: constants.UDP,
			},
		},
		"tcp_ipv6": {
			network: constants.TCP + "6",
			address: "[2001:db8::53]:53",
			connection: models.Connection{
				IP:       netip.MustParseAddr("2001:db8::53"),
				Port:     53,
				Protocol: constants.TCP,
			},
		},
		"unsupported_network": {
			network:    "ip",
			address:    "100.100.100.100:53",
			errMessage: "DNS network is not supported",
		},
		"invalid_address": {
			network:    constants.UDP,
			address:    "invalid",
			errMessage: "parsing DNS resolver address",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			connection, err := dnsConnection(testCase.network, testCase.address)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.connection, connection)
		})
	}
}
