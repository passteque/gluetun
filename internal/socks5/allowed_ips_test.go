package socks5

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ipAllowed(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		allowedIPs []netip.Prefix
		ip         netip.Addr
		expected   bool
	}{
		"empty_list_allows_all": {
			ip:       netip.MustParseAddr("192.168.1.1"),
			expected: true,
		},
		"ipv4_exact_match": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")},
			ip:         netip.MustParseAddr("192.168.1.2"),
			expected:   true,
		},
		"ipv4_in_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			ip:         netip.MustParseAddr("10.20.30.40"),
			expected:   true,
		},
		"ipv4_not_in_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ip:         netip.MustParseAddr("192.168.2.1"),
			expected:   false,
		},
		"ipv6_in_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			ip:         netip.MustParseAddr("2001:db8:1234::1"),
			expected:   true,
		},
		"ipv6_not_in_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("2001:db9::/32")},
			ip:         netip.MustParseAddr("2001:db8:1234::1"),
			expected:   false,
		},
		"ipv4_ip_with_ipv6_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			ip:         netip.MustParseAddr("192.168.1.1"),
			expected:   false,
		},
		"ipv6_ip_with_ipv4_network": {
			allowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ip:         netip.MustParseAddr("2001:db8::1"),
			expected:   false,
		},
		"multiple_networks_match_second": {
			allowedIPs: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("10.0.0.0/8"),
			},
			ip:       netip.MustParseAddr("10.0.0.1"),
			expected: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := ipAllowed(testCase.allowedIPs, testCase.ip)

			assert.Equal(t, testCase.expected, result)
		})
	}
}
