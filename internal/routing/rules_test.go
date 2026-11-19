package routing

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func makeNetipPrefix(n byte) netip.Prefix {
	const bits = 24
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{n, n, n, 0}), bits)
}

func makeIPRule(src, dst netip.Prefix,
	table uint32, priority uint32,
) netlink.Rule {
	family := netlink.FamilyV4
	if (src.IsValid() && src.Addr().Is6()) || (dst.IsValid() && dst.Addr().Is6()) {
		family = netlink.FamilyV6
	}
	return netlink.Rule{
		Priority: &priority,
		Family:   family,
		Table:    table,
		Src:      src,
		Dst:      dst,
		Action:   netlink.ActionToTable,
	}
}

func Test_Routing_addIPRule(t *testing.T) {
	t.Parallel()

	errDummy := errors.New("dummy error")

	type ruleListCall struct {
		rules []netlink.Rule
		err   error
	}

	type ruleAddCall struct {
		expected  bool
		ruleToAdd netlink.Rule
		err       error
	}

	testCases := map[string]struct {
		src      netip.Prefix
		dst      netip.Prefix
		table    uint32
		priority uint32
		ruleList ruleListCall
		ruleAdd  ruleAddCall
		err      error
	}{
		"list error": {
			ruleList: ruleListCall{
				err: errDummy,
			},
			err: errors.New("listing rules: dummy error"),
		},
		"rule already exists": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleList: ruleListCall{
				rules: []netlink.Rule{
					makeIPRule(makeNetipPrefix(2), makeNetipPrefix(2), 99, 99),
					makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
				},
			},
		},
		"add rule error": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleAdd: ruleAddCall{
				expected:  true,
				ruleToAdd: makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
				err:       errDummy,
			},
			err: errors.New("adding ip rule 99: from 1.1.1.0/24 to 2.2.2.0/24 table 99: dummy error"),
		},
		"add rule success": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleList: ruleListCall{
				rules: []netlink.Rule{
					makeIPRule(makeNetipPrefix(2), makeNetipPrefix(2), 99, 99),
					makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 101, 101),
				},
			},
			ruleAdd: ruleAddCall{
				expected:  true,
				ruleToAdd: makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			netLinker := NewMockNetLinker(ctrl)
			netLinker.EXPECT().RuleList(netlink.FamilyAll).
				Return(testCase.ruleList.rules, testCase.ruleList.err)
			if testCase.ruleAdd.expected {
				netLinker.EXPECT().RuleAdd(testCase.ruleAdd.ruleToAdd).
					Return(testCase.ruleAdd.err)
			}

			r := Routing{
				netLinker: netLinker,
			}

			err := r.addIPRule(testCase.src, testCase.dst,
				testCase.table, testCase.priority)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Routing_deleteIPRule(t *testing.T) {
	t.Parallel()

	errDummy := errors.New("dummy error")

	type ruleListCall struct {
		rules []netlink.Rule
		err   error
	}

	type ruleDelCall struct {
		expected  bool
		ruleToDel netlink.Rule
		err       error
	}

	testCases := map[string]struct {
		src      netip.Prefix
		dst      netip.Prefix
		table    uint32
		priority uint32
		ruleList ruleListCall
		ruleDel  ruleDelCall
		err      error
	}{
		"list error": {
			ruleList: ruleListCall{
				err: errDummy,
			},
			err: errors.New("listing rules: dummy error"),
		},
		"rule delete error": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleList: ruleListCall{
				rules: []netlink.Rule{
					makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
				},
			},
			ruleDel: ruleDelCall{
				expected:  true,
				ruleToDel: makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
				err:       errDummy,
			},
			err: errors.New("deleting rule ip rule 99: from 1.1.1.0/24 to 2.2.2.0/24 table 99: dummy error"),
		},
		"rule deleted": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleList: ruleListCall{
				rules: []netlink.Rule{
					makeIPRule(makeNetipPrefix(2), makeNetipPrefix(2), 99, 99),
					makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
				},
			},
			ruleDel: ruleDelCall{
				expected:  true,
				ruleToDel: makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 99, 99),
			},
		},
		"rule does not exist": {
			src:      makeNetipPrefix(1),
			dst:      makeNetipPrefix(2),
			table:    99,
			priority: 99,
			ruleList: ruleListCall{
				rules: []netlink.Rule{
					makeIPRule(makeNetipPrefix(2), makeNetipPrefix(2), 99, 99),
					makeIPRule(makeNetipPrefix(1), makeNetipPrefix(2), 101, 101),
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			netLinker := NewMockNetLinker(ctrl)
			netLinker.EXPECT().RuleList(netlink.FamilyAll).
				Return(testCase.ruleList.rules, testCase.ruleList.err)
			if testCase.ruleDel.expected {
				netLinker.EXPECT().RuleDel(testCase.ruleDel.ruleToDel).
					Return(testCase.ruleDel.err)
			}

			r := Routing{
				netLinker: netLinker,
			}

			err := r.deleteIPRule(testCase.src, testCase.dst,
				testCase.table, testCase.priority)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func ptrTo[T any](v T) *T { return &v }

func Test_rulesAreEqual(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		a     netlink.Rule
		b     netlink.Rule
		equal bool
	}{
		"both_empty": {
			equal: true,
		},
		"not_equal_by_src": {
			a: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{9, 9, 9, 9}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
			b: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
		},
		"not_equal_by_dst": {
			a: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{9, 9, 9, 9}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
			b: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
		},
		"not_equal_by_priority": {
			a: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(999)),
				Table:    101,
			},
			b: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
		},
		"not_equal_by_table": {
			a: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    102,
			},
			b: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
		},
		"equal": {
			a: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
			b: netlink.Rule{
				Src:      netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
				Dst:      netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				Priority: ptrTo(uint32(100)),
				Table:    101,
			},
			equal: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			equal := rulesAreEqual(testCase.a, testCase.b)

			assert.Equal(t, testCase.equal, equal)
		})
	}
}

func Test_ipPrefixesAreEqual(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		a     netip.Prefix
		b     netip.Prefix
		equal bool
	}{
		"both_not_valid": {
			equal: true,
		},
		"first_not_valid": {
			b: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
		},
		"second_not_valid": {
			a: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
		},
		"both_equal": {
			a:     netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
			b:     netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
			equal: true,
		},
		"both_not_equal_by_IP": {
			a: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
			b: netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 24),
		},
		"both_not_equal_by_bits": {
			a: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
			b: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
		},
		"both_not_equal_by_IP_and_bits": {
			a: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 24),
			b: netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			equal := ipPrefixesAreEqual(testCase.a, testCase.b)

			assert.Equal(t, testCase.equal, equal)
		})
	}
}
