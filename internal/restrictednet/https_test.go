package restrictednet

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/assert"
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

type destinationAddrPortMatcher struct {
	expected netip.AddrPort
}

func (m destinationAddrPortMatcher) Matches(x any) bool {
	ip, ok := x.(netip.AddrPort)
	if !ok {
		return false
	}
	if m.expected.IsValid() {
		return ip == m.expected
	}
	return ip.IsValid() && ip.Port() == m.expected.Port()
}

func (m destinationAddrPortMatcher) String() string {
	if m.expected.IsValid() {
		return "is the same as " + m.expected.String()
	}
	return "matches the port " + fmt.Sprint(m.expected.Port())
}

func Test_Client_OpenHTTPS(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ctrl := gomock.NewController(t)

	const destinationTLSName = "one.one.one.one"
	destinationAddrPort := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 443)

	firewall := NewMockFirewall(ctrl)
	sourceMatcher := listenAddrPortMatcher{}
	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		ctx, "tcp", "eth0", sourceMatcher, destinationAddrPort, false,
	).DoAndReturn(func(_ context.Context,
		_, _ string, source, _ netip.AddrPort, _ bool,
	) error {
		sourceMatcher.expected = source
		return nil
	})
	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		context.Background(), "tcp", "eth0", sourceMatcher, destinationAddrPort, true,
	)

	const ipv6Supported = false
	upstreamResolvers := []provider.Provider{provider.Google()}
	settings := Settings{
		Firewall:          firewall,
		DefaultInterface:  "eth0",
		IPv6Supported:     ptrTo(ipv6Supported),
		UpstreamResolvers: upstreamResolvers,
	}
	client := New(settings)

	httpClient, cleanup, err := client.OpenHTTPS(ctx, destinationTLSName, destinationAddrPort)
	require.NoError(t, err)
	require.NotNil(t, httpClient)
	require.NotNil(t, cleanup)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+destinationTLSName, nil)
	require.NoError(t, err)

	response, err := httpClient.Do(request)
	t.Cleanup(func() {
		response.Body.Close()
	})
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.StatusCode)

	err = cleanup()
	require.NoError(t, err)
}
