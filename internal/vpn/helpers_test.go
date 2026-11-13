package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_pickResolvedIP(t *testing.T) {
	t.Parallel()

	ipv4a := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	ipv4b := netip.AddrFrom4([4]byte{5, 6, 7, 8})
	ipv6a := netip.MustParseAddr("2001:db8::1")
	ipv6b := netip.MustParseAddr("2001:db8::2")

	testCases := map[string]struct {
		addresses     []netip.Addr
		ipv6Supported bool
		expected      netip.Addr
	}{
		"ipv4 only, ipv6 not supported": {
			addresses:     []netip.Addr{ipv4a, ipv4b},
			ipv6Supported: false,
			expected:      ipv4a,
		},
		"ipv4 only, ipv6 supported": {
			addresses:     []netip.Addr{ipv4a, ipv4b},
			ipv6Supported: true,
			expected:      ipv4a,
		},
		"mixed, ipv6 supported prefers ipv6": {
			addresses:     []netip.Addr{ipv4a, ipv6a, ipv6b},
			ipv6Supported: true,
			expected:      ipv6a,
		},
		"mixed, ipv6 not supported picks ipv4": {
			addresses:     []netip.Addr{ipv6a, ipv4a, ipv4b},
			ipv6Supported: false,
			expected:      ipv4a,
		},
		"ipv6 only, ipv6 supported": {
			addresses:     []netip.Addr{ipv6a, ipv6b},
			ipv6Supported: true,
			expected:      ipv6a,
		},
		"ipv6 only, ipv6 not supported falls back to first": {
			addresses:     []netip.Addr{ipv6a, ipv6b},
			ipv6Supported: false,
			expected:      ipv6a,
		},
		"single address": {
			addresses:     []netip.Addr{ipv4a},
			ipv6Supported: false,
			expected:      ipv4a,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := pickResolvedIP(testCase.addresses, testCase.ipv6Supported)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

type mockResolver struct {
	addresses []netip.Addr
	err       error
}

func (m *mockResolver) ResolveName(_ context.Context, _ string) ([]netip.Addr, error) {
	return m.addresses, m.err
}

type mockInfoLogger struct{}

func (m *mockInfoLogger) Info(_ string) {}

func Test_resolveEndpoint(t *testing.T) {
	t.Parallel()

	ipv4 := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	ipv6 := netip.MustParseAddr("2001:db8::1")

	testCases := map[string]struct {
		resolver      Resolver
		hostname      string
		ipv6Supported bool
		expectedIP    netip.Addr
		errMessage    string
	}{
		"success ipv4": {
			resolver:      &mockResolver{addresses: []netip.Addr{ipv4}},
			hostname:      "myhost.dyndns.org",
			ipv6Supported: false,
			expectedIP:    ipv4,
		},
		"success prefers ipv6 when supported": {
			resolver:      &mockResolver{addresses: []netip.Addr{ipv4, ipv6}},
			hostname:      "myhost.dyndns.org",
			ipv6Supported: true,
			expectedIP:    ipv6,
		},
		"resolution error": {
			resolver:      &mockResolver{err: errors.New("DoH unreachable")},
			hostname:      "myhost.dyndns.org",
			ipv6Supported: false,
			errMessage:    "resolving endpoint hostname \"myhost.dyndns.org\": DoH unreachable",
		},
		"no addresses returned": {
			resolver:      &mockResolver{addresses: nil},
			hostname:      "myhost.dyndns.org",
			ipv6Supported: false,
			errMessage:    "resolving endpoint hostname \"myhost.dyndns.org\": no IP address found",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ip, err := resolveEndpoint(t.Context(), testCase.resolver,
				testCase.hostname, testCase.ipv6Supported, &mockInfoLogger{})

			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errMessage)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.expectedIP, ip)
			}
		})
	}
}
