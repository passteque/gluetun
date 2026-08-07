package nftables

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_deleteRule(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "test_filter",
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "test_output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	testCases := map[string]struct {
		setupRules     func(t *testing.T, fw *Firewall)
		ruleToDelete   func(fw *Firewall) *nftables.Rule
		expectError    bool
		expectErrorIs  error
		expectRulesLen int
	}{
		"rule not found": {
			setupRules: func(_ *testing.T, _ *Firewall) {
				// No rules added
			},
			ruleToDelete: func(_ *Firewall) *nftables.Rule {
				return &nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
				}
			},
			expectError:    true,
			expectErrorIs:  errRuleToDeleteNotFound,
			expectRulesLen: 0,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fw := &Firewall{rules: []*nftables.Rule{}}
			tc.setupRules(t, fw)
			ruleToDelete := tc.ruleToDelete(fw)

			err := fw.deleteRule(conn, ruleToDelete)

			if tc.expectError {
				require.Error(t, err)
				if tc.expectErrorIs != nil {
					assert.ErrorIs(t, err, tc.expectErrorIs)
				}
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, fw.rules, tc.expectRulesLen)
		})
	}
}

//nolint:paralleltest
func Test_deleteRule_withFlushing(t *testing.T) {
	// Not parallel: requires root access for nftables handle assignment.
	t.Skip("requires root access for nftables handle assignment")

	conn, err := nftables.New()
	require.NoError(t, err)

	// Create a unique table for this test
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "test_filter_del_" + strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "test_output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	// Clean up after test
	t.Cleanup(func() {
		conn.FlushRuleset()
	})

	// Add some rules and flush to get handles
	// Use valid expressions: Meta type match + Verdict (like "meta nfproto ipv4 accept")
	rules := make([]*nftables.Rule, 3)
	for i := range rules {
		nfprotoVal := uint16(2) // ip
		if i > 0 {
			nfprotoVal = uint16(10) // ipv6
		}
		rules[i] = conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, byte(nfprotoVal)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
	err = conn.Flush()
	require.NoError(t, err)

	fw := &Firewall{rules: rules}

	// Delete middle rule
	err = fw.deleteRule(conn, rules[1])
	require.NoError(t, err)
	assert.Len(t, fw.rules, 2)

	// Delete first rule
	err = fw.deleteRule(conn, rules[0])
	require.NoError(t, err)
	assert.Len(t, fw.rules, 1)

	// Try to delete a rule that doesn't exist in fw.rules
	nonExistentRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	}
	err = fw.deleteRule(conn, nonExistentRule)
	require.Error(t, err)
	assert.ErrorIs(t, err, errRuleToDeleteNotFound)
	assert.Len(t, fw.rules, 1)
}
