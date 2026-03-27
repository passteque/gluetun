package wireguard

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_addRoute(t *testing.T) {
	t.Parallel()

	const linkIndex = 88

	ipPrefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32)

	const firewallMark = 51820

	errDummy := errors.New("dummy")

	testCases := map[string]struct {
		dst           netip.Prefix
		expectedRoute netlink.Route
		routeAddErr   error
		err           error
	}{
		"success": {
			dst: ipPrefix,
			expectedRoute: netlink.Route{
				LinkIndex: linkIndex,
				Dst:       ipPrefix,
				Family:    netlink.FamilyV4,
				Table:     firewallMark,
				Type:      netlink.RouteTypeUnicast,
				Scope:     netlink.ScopeUniverse,
				Proto:     netlink.ProtoStatic,
			},
		},
		"route add error": {
			dst: ipPrefix,
			expectedRoute: netlink.Route{
				LinkIndex: linkIndex,
				Dst:       ipPrefix,
				Family:    netlink.FamilyV4,
				Table:     firewallMark,
				Type:      netlink.RouteTypeUnicast,
				Scope:     netlink.ScopeUniverse,
				Proto:     netlink.ProtoStatic,
			},
			routeAddErr: errDummy,
			err:         errors.New("adding route for link with index 88, destination 1.2.3.4/32 and table 51820: dummy"), //nolint:lll
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			netLinker := NewMockNetLinker(ctrl)
			netLinker.EXPECT().
				RouteAdd(testCase.expectedRoute).
				Return(testCase.routeAddErr)

			err := addRoute(linkIndex, testCase.dst, firewallMark, netLinker)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
