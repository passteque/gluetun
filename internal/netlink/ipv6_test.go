package netlink

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isUnusableRouteType(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		routeType int
		expected  bool
	}{
		"unreachable": {routeTypeUnreachable, true},
		"prohibit":    {routeTypeProhibit, true},
		"blackhole":   {routeTypeBlackhole, true},
		// Linux route types that can deliver packets, see
		// include/uapi/linux/rtnetlink.h.
		"unspecified": {0, false},
		"unicast":     {1, false},
		"local":       {2, false},
		"broadcast":   {3, false},
		"anycast":     {4, false},
		"multicast":   {5, false},
		"throw":       {9, false},
		"nat":         {10, false},
		"xresolve":    {11, false},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected,
				isUnusableRouteType(testCase.routeType))
		})
	}
}

func Test_isIPv6SupportEvidence(t *testing.T) {
	t.Parallel()

	// Linux route types, see include/uapi/linux/rtnetlink.h.
	const (
		typeUnicast   int = 1
		typeLocal     int = 2
		typeMulticast int = 5
	)

	testCases := map[string]struct {
		route    Route
		expected bool
	}{
		"default_route_no_destination": {
			route:    Route{Type: typeUnicast},
			expected: true,
		},
		"default_route_unspecified_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("::/0"),
				Type: typeUnicast,
			},
			expected: true,
		},
		"global_unicast_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("2a01:4f8:1234::/64"),
				Type: typeUnicast,
			},
			expected: true,
		},
		"unique_local_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("fd42:bd4c:c56d::/64"),
				Type: typeUnicast,
			},
			expected: true,
		},
		"link_local_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("fe80::/64"),
				Type: typeUnicast,
			},
			expected: false,
		},
		"link_local_address_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("fe80::42:acff:fe11:2/128"),
				Type: typeLocal,
			},
			expected: false,
		},
		"multicast_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("ff00::/8"),
				Type: typeMulticast,
			},
			expected: false,
		},
		"loopback_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("::1/128"),
				Type: typeLocal,
			},
			expected: false,
		},
		"ipv4_destination": {
			route: Route{
				Dst:  netip.MustParsePrefix("172.20.0.0/16"),
				Type: typeUnicast,
			},
			expected: false,
		},
		"ipv4_source": {
			route: Route{
				Src:  netip.MustParseAddr("172.20.0.2"),
				Type: typeUnicast,
			},
			expected: false,
		},
		"unreachable_type": {
			route: Route{
				Dst:  netip.MustParsePrefix("2a01:4f8:1234::/64"),
				Type: routeTypeUnreachable,
			},
			expected: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected, isIPv6SupportEvidence(testCase.route))
		})
	}
}
