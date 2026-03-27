package wireguard

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AddAddresses(t *testing.T) {
	t.Parallel()

	ipNetOne := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32)
	ipNetTwo := netip.PrefixFrom(netip.MustParseAddr("::1234"), 64)

	errDummy := errors.New("dummy")

	testCases := map[string]struct {
		linkIndex      uint32
		addrs          []netip.Prefix
		ipv6           bool
		netlinkBuilder func(ctrl *gomock.Controller, linkIndex uint32) *MockNetLinker
		err            error
	}{
		"success": {
			linkIndex: 1,
			addrs:     []netip.Prefix{ipNetOne, ipNetTwo},
			ipv6:      true,
			netlinkBuilder: func(ctrl *gomock.Controller, linkIndex uint32) *MockNetLinker {
				netLinker := NewMockNetLinker(ctrl)
				firstCall := netLinker.EXPECT().
					AddrReplace(linkIndex, ipNetOne).
					Return(nil)
				netLinker.EXPECT().
					AddrReplace(linkIndex, ipNetTwo).
					Return(nil).After(firstCall)
				return netLinker
			},
		},
		"first add error": {
			linkIndex: 1,
			addrs:     []netip.Prefix{ipNetOne, ipNetTwo},
			ipv6:      true,
			netlinkBuilder: func(ctrl *gomock.Controller, linkIndex uint32) *MockNetLinker {
				netLinker := NewMockNetLinker(ctrl)
				netLinker.EXPECT().
					AddrReplace(linkIndex, ipNetOne).
					Return(errDummy)
				return netLinker
			},
			err: errors.New("dummy: when adding address 1.2.3.4/32 to link with index 1"),
		},
		"second add error": {
			linkIndex: 1,
			addrs:     []netip.Prefix{ipNetOne, ipNetTwo},
			ipv6:      true,
			netlinkBuilder: func(ctrl *gomock.Controller, linkIndex uint32) *MockNetLinker {
				netLinker := NewMockNetLinker(ctrl)
				firstCall := netLinker.EXPECT().
					AddrReplace(linkIndex, ipNetOne).
					Return(nil)
				netLinker.EXPECT().
					AddrReplace(linkIndex, ipNetTwo).
					Return(errDummy).After(firstCall)
				return netLinker
			},
			err: errors.New("dummy: when adding address ::1234/64 to link with index 1"),
		},
		"ignore IPv6": {
			addrs: []netip.Prefix{ipNetTwo},
			netlinkBuilder: func(_ *gomock.Controller, _ uint32) *MockNetLinker {
				return NewMockNetLinker(nil)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			netlink := testCase.netlinkBuilder(ctrl, testCase.linkIndex)

			err := AddAddresses(testCase.linkIndex, testCase.addrs, testCase.ipv6, netlink)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
