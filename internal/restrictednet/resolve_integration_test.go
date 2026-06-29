//go:build integration

package restrictednet

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Client_ResolveName(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ctrl := gomock.NewController(t)

	firewall := NewMockFirewall(ctrl)
	sourceMatcher := listenAddrPortMatcher{}
	destinationMatcher := destinationAddrPortMatcher{
		expected: netip.AddrPortFrom(netip.Addr{}, 443),
	}

	// Add rule
	firstCall := firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		ctx, "tcp", "eth0", sourceMatcher, destinationMatcher, false,
	).DoAndReturn(func(
		_ context.Context, _, _ string, source, destination netip.AddrPort, _ bool,
	) error {
		sourceMatcher.expected = source
		destinationMatcher.expected = destination
		return nil
	})

	// Removal rule
	firewall.EXPECT().AcceptOutputFromIPPortToIPPort(
		context.Background(), "tcp", "eth0", sourceMatcher, destinationMatcher, true,
	).Return(nil).After(firstCall)

	settings := Settings{
		DefaultInterface:  "eth0",
		IPv6Supported:     ptrTo(false),
		Firewall:          firewall,
		UpstreamResolvers: []provider.Provider{provider.Cloudflare()},
	}
	client := New(settings)

	addresses, err := client.ResolveName(ctx, "github.com")
	require.NoError(t, err)
	assert.NotEmpty(t, addresses)
}

func Test_answersToNetipAddrs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		message  *dns.Msg
		expected []netip.Addr
	}{
		"nil_message": {},
		"no_answers": {
			message:  &dns.Msg{},
			expected: []netip.Addr{},
		},
		"a_record": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{1, 1, 1, 1},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		},
		"aaaa_record": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
		},
		"mixed_records": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{1, 1, 1, 1},
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			addresses := answersToNetipAddrs(testCase.message)
			assert.Equal(t, testCase.expected, addresses)
		})
	}
}
