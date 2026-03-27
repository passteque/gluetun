//go:build linux

package wireguard

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopDebugLogger struct{}

func (n noopDebugLogger) Debug(_ string)            {}
func (n noopDebugLogger) Debugf(_ string, _ ...any) {}
func (n noopDebugLogger) Info(_ string)             {}
func (n noopDebugLogger) Error(_ string)            {}
func (n noopDebugLogger) Errorf(_ string, _ ...any) {}
func (n noopDebugLogger) Patch(_ ...log.Option)     {}

func Test_AddAddresses_Integration(t *testing.T) {
	t.Parallel()

	netlinker := netlink.New(&noopDebugLogger{})

	link := netlink.Link{
		DeviceType:  netlink.DeviceTypeNone,
		VirtualType: "bridge",
		Name:        makeLinkName(),
	}

	linkIndex, err := netlinker.LinkAdd(link)
	require.NoError(t, err)
	link.Index = linkIndex

	defer func() {
		err = netlinker.LinkDel(linkIndex)
		assert.NoError(t, err)
	}()

	addresses := []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 32),
	}

	wg := &Wireguard{
		netlink: netlinker,
		settings: Settings{
			IPv6: new(bool),
		},
	}

	const addIterations = 2 // initial + replace
	for range addIterations {
		err = AddAddresses(link.Index, addresses, *wg.settings.IPv6, wg.netlink)
		require.NoError(t, err)

		ipPrefixes, err := netlinker.AddrList(link.Index, netlink.FamilyAll)
		require.NoError(t, err)
		require.Equal(t, len(addresses), len(ipPrefixes))
		for i, ipPrefix := range ipPrefixes {
			assert.Equal(t, addresses[i], ipPrefix)
		}
	}
}

func Test_AddRule_Integration(t *testing.T) {
	t.Parallel()

	logger := &noopDebugLogger{}
	netlinker := netlink.New(logger)

	// Unique combination for this test
	const rulePriority uint32 = 10000
	const firewallMark uint32 = 12345
	const family = netlink.FamilyV4

	cleanup, err := AddRule(rulePriority,
		firewallMark, family, netlinker, logger)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := cleanup()
		assert.NoError(t, err)
	})

	rules, err := netlinker.RuleList(netlink.FamilyV4)
	require.NoError(t, err)
	expectedRule := netlink.Rule{
		Priority: ptrTo(rulePriority),
		Family:   netlink.FamilyV4,
		Table:    firewallMark,
		Mark:     ptrTo(firewallMark),
		Flags:    netlink.FlagInvert,
		Action:   netlink.ActionToTable,
	}
	var rule netlink.Rule
	var ruleFound bool
	for _, rule = range rules {
		if rulesAreEqual(rule, expectedRule) {
			ruleFound = true
			break
		}
	}
	require.True(t, ruleFound)

	// Existing rule cannot be added
	nilCleanup, err := AddRule(rulePriority,
		firewallMark, family, netlinker, logger)
	if nilCleanup != nil {
		_ = nilCleanup() // in case it succeeds
	}
	require.Error(t, err)
	assert.EqualError(t, err, "adding ip rule 10000: from all to all table 12345: netlink receive: file exists")
}
