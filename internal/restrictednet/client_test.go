package restrictednet

import (
	"context"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/require"
)

type listenAddrPortMatcher struct {
	expected netip.AddrPort
}

func (m listenAddrPortMatcher) Matches(x any) bool {
	ip, ok := x.(netip.AddrPort)
	if !ok {
		return false
	}
	if m.expected.IsValid() {
		return ip == m.expected
	}
	return ip.IsValid() && ip.Addr().IsValid() && ip.Port() > 0
}

func (m listenAddrPortMatcher) String() string {
	if m.expected.IsValid() {
		return "is the same as " + m.expected.String()
	}
	return "is a valid netip.AddrPort with a valid IP and non-zero port"
}

func Test_Client_OpenHTTPS(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	firewall := NewMockFirewall(ctrl)

	destination := netip.MustParseAddrPort("1.2.3.4:443")
	backgroundContext := context.Background()
	sourceMatcher := listenAddrPortMatcher{}
	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		backgroundContext, "tcp", "eth0", sourceMatcher, destination, false,
	).DoAndReturn(func(_ context.Context,
		_, _ string, source, _ netip.AddrPort, _ bool,
	) error {
		sourceMatcher.expected = source
		return nil
	})
	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		backgroundContext, "tcp", "eth0", sourceMatcher, destination, true,
	)

	const ipv6Supported = false
	upstreamResolvers := []provider.Provider{provider.Google()}
	client, err := New(firewall, "eth0", ipv6Supported, upstreamResolvers)
	require.NoError(t, err)

	httpClient, cleanup, err := client.OpenHTTPS("api.example.com", netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.NotNil(t, httpClient)
	require.NotNil(t, cleanup)

	err = cleanup()
	require.NoError(t, err)
}
