//go:build linux

package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_AcceptInputThroughInterface(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf     string
		expected []expr.Any
	}{
		"named_interface": {
			intf: "eth0",
			expected: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("eth0\x00")},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		},
		"empty_interface": {
			intf:     "",
			expected: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		},
		"all_interface": {
			intf:     "*",
			expected: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			mockConn.EXPECT().ListTables().Return(nil, nil)
			mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
				return table
			})
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			}).Times(3)

			var addedRule *nftables.Rule
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRule = rule
				return rule
			})
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptInputThroughInterface(t.Context(), testCase.intf)

			assert.NoError(t, err)
			assert.NotNil(t, addedRule)
			assert.Equal(t, inputChainName, addedRule.Chain.Name)
			assert.Equal(t, testCase.expected, addedRule.Exprs)
			assert.Len(t, f.rules, 1)
		})
	}
}

func Test_AcceptInputToPort(t *testing.T) {
	t.Parallel()

	port := uint16(443)

	buildRuleExprs := func(protocol uint8) []expr.Any {
		exprs := append(protocolExprs(protocol), destinationPortExprs(port)...)
		return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	}

	testCases := map[string]struct {
		intf    string
		remove  bool
		tracked []*nftables.Rule
	}{
		"add_no_interface":   {intf: ""},
		"add_with_interface": {intf: "tun0"},
		"remove": {
			intf:   "tun0",
			remove: true,
			tracked: []*nftables.Rule{
				{Exprs: withInterface(buildRuleExprs(protocolTCP), "tun0")},
				{Exprs: withInterface(buildRuleExprs(protocolUDP), "tun0")},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }, rules: testCase.tracked}

			mockConn.EXPECT().ListTables().Return(nil, nil)
			mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
				return table
			})
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			}).Times(3)

			var addedRules []*nftables.Rule
			if !testCase.remove {
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRules = append(addedRules, rule)
					return rule
				}).Times(2)
			} else {
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).DoAndReturn(
					func(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
						// Return the kernel rules matching the tracked rules.
						var kernelRules []*nftables.Rule
						handle := uint64(1)
						for _, tracked := range testCase.tracked {
							kernelRules = append(kernelRules, &nftables.Rule{
								Table: table, Chain: chain, Handle: handle, Exprs: tracked.Exprs,
							})
							handle++
						}
						return kernelRules, nil
					},
				).Times(2)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil).Times(2)
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptInputToPort(t.Context(), testCase.intf, port, testCase.remove)

			assert.NoError(t, err)

			if !testCase.remove {
				assert.Len(t, addedRules, 2)
				expectedTCP := withInterface(buildRuleExprs(protocolTCP), testCase.intf)
				expectedUDP := withInterface(buildRuleExprs(protocolUDP), testCase.intf)
				assert.Equal(t, expectedTCP, addedRules[0].Exprs)
				assert.Equal(t, expectedUDP, addedRules[1].Exprs)
				for _, rule := range addedRules {
					assert.Equal(t, inputChainName, rule.Chain.Name)
				}
				assert.Len(t, f.rules, 2)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}

func Test_AcceptInputToSubnet(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf   string
		subnet netip.Prefix
	}{
		"ipv4_with_interface": {
			intf:   "tun0",
			subnet: netip.MustParsePrefix("10.0.0.0/8"),
		},
		"ipv6_no_interface": {
			intf:   "",
			subnet: netip.MustParsePrefix("fd00::/8"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			mockConn.EXPECT().ListTables().Return(nil, nil)
			mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
				return table
			})
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			}).Times(3)

			var addedRule *nftables.Rule
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRule = rule
				return rule
			})
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptInputToSubnet(t.Context(), testCase.intf, testCase.subnet)

			assert.NoError(t, err)
			assert.NotNil(t, addedRule)
			assert.Equal(t, inputChainName, addedRule.Chain.Name)

			expected := append(inputInterfaceExprs(testCase.intf), destinationSubnetExprs(testCase.subnet)...)
			expected = append(expected, &expr.Verdict{Kind: expr.VerdictAccept})
			assert.Equal(t, expected, addedRule.Exprs)
			assert.Len(t, f.rules, 1)
		})
	}
}

// withInterface prepends the given interface's input expressions to exprs, if
// the interface is not empty or "*".
func withInterface(exprs []expr.Any, intf string) []expr.Any {
	return append(inputInterfaceExprs(intf), exprs...)
}
