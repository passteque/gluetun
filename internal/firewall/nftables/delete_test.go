//go:build linux

package nftables

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func testAcceptExprs() []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
}

func Test_deleteRule(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	chain := &nftables.Chain{Name: inputChainName, Table: table}
	exprs := testAcceptExprs()
	rule := &nftables.Rule{Table: table, Chain: chain, Exprs: exprs}
	otherExprs := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}

	testCases := map[string]struct {
		tracked       []*nftables.Rule
		kernelRules   []*nftables.Rule
		getRulesError error
		delRuleError  error
		expectedError string
		expectDel     bool
	}{
		"rule_not_tracked": {
			tracked:       nil,
			expectedError: "rule not found for removal",
		},
		"tracked_rule_found": {
			tracked:     []*nftables.Rule{rule},
			kernelRules: []*nftables.Rule{{Table: table, Chain: chain, Handle: 42, Exprs: exprs}},
			expectDel:   true,
		},
		"tracked_rule_found_among_others": {
			tracked: []*nftables.Rule{rule},
			kernelRules: []*nftables.Rule{
				{Table: table, Chain: chain, Handle: 7, Exprs: otherExprs},
				{Table: table, Chain: chain, Handle: 42, Exprs: exprs},
			},
			expectDel: true,
		},
		"tracked_rule_not_in_kernel": {
			tracked:       []*nftables.Rule{rule},
			kernelRules:   []*nftables.Rule{{Table: table, Chain: chain, Handle: 7, Exprs: otherExprs}},
			expectedError: "rule not found for removal",
		},
		"get_rules_error": {
			tracked:       []*nftables.Rule{rule},
			getRulesError: errors.New("get rules failed"),
			expectedError: "fetching rules for deletion: get rules failed",
		},
		"del_rule_error": {
			tracked:       []*nftables.Rule{rule},
			kernelRules:   []*nftables.Rule{{Table: table, Chain: chain, Handle: 42, Exprs: exprs}},
			delRuleError:  errors.New("del rule failed"),
			expectedError: "del rule failed",
			expectDel:     true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{rules: testCase.tracked}

			if testCase.tracked != nil {
				mockConn.EXPECT().GetRules(table, chain).Return(testCase.kernelRules, testCase.getRulesError)
				if testCase.expectDel {
					mockConn.EXPECT().DelRule(gomock.Any()).DoAndReturn(
						func(existing *nftables.Rule) error {
							assert.Equal(t, uint64(42), existing.Handle)
							return testCase.delRuleError
						},
					)
				}
			}

			err := f.deleteRule(mockConn, rule)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func Test_trackedRuleIndex(t *testing.T) {
	t.Parallel()

	exprs := testAcceptExprs()
	rule := &nftables.Rule{Exprs: exprs}
	otherRule := &nftables.Rule{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}}

	testCases := map[string]struct {
		rules    []*nftables.Rule
		lookup   *nftables.Rule
		expected int
	}{
		"empty": {
			rules:    nil,
			lookup:   rule,
			expected: -1,
		},
		"not_found": {
			rules:    []*nftables.Rule{otherRule},
			lookup:   rule,
			expected: -1,
		},
		"found_first": {
			rules:    []*nftables.Rule{rule, otherRule},
			lookup:   rule,
			expected: 0,
		},
		"found_last": {
			rules:    []*nftables.Rule{otherRule, rule},
			lookup:   rule,
			expected: 1,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := &Firewall{rules: testCase.rules}
			assert.Equal(t, testCase.expected, f.trackedRuleIndex(testCase.lookup))
		})
	}
}

func Test_removeTrackedRule(t *testing.T) {
	t.Parallel()

	exprsA := testAcceptExprs()
	exprsB := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	ruleA := &nftables.Rule{Exprs: exprsA}
	ruleB := &nftables.Rule{Exprs: exprsB}

	testCases := map[string]struct {
		rules    []*nftables.Rule
		index    int
		expected []*nftables.Rule
	}{
		"first": {
			rules:    []*nftables.Rule{ruleA, ruleB},
			index:    0,
			expected: []*nftables.Rule{ruleB},
		},
		"last": {
			rules:    []*nftables.Rule{ruleA, ruleB},
			index:    1,
			expected: []*nftables.Rule{ruleA},
		},
		"only": {
			rules:    []*nftables.Rule{ruleA},
			index:    0,
			expected: []*nftables.Rule{},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := &Firewall{rules: testCase.rules}
			f.removeTrackedRule(testCase.index)
			assert.Equal(t, testCase.expected, f.rules)
		})
	}
}

func Test_untrackRule(t *testing.T) {
	t.Parallel()

	exprsA := testAcceptExprs()
	exprsB := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	ruleA := &nftables.Rule{Exprs: exprsA}
	ruleB := &nftables.Rule{Exprs: exprsB}

	testCases := map[string]struct {
		rules    []*nftables.Rule
		lookup   *nftables.Rule
		expected []*nftables.Rule
	}{
		"tracked": {
			rules:    []*nftables.Rule{ruleA, ruleB},
			lookup:   ruleA,
			expected: []*nftables.Rule{ruleB},
		},
		"not_tracked": {
			rules:    []*nftables.Rule{ruleA},
			lookup:   ruleB,
			expected: []*nftables.Rule{ruleA},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := &Firewall{rules: testCase.rules}
			f.untrackRule(testCase.lookup)
			assert.Equal(t, testCase.expected, f.rules)
		})
	}
}

func Test_addOrRemoveRule(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	chain := &nftables.Chain{Name: inputChainName, Table: table}
	exprs := testAcceptExprs()
	rule := &nftables.Rule{Table: table, Chain: chain, Exprs: exprs}

	testCases := map[string]struct {
		tracked       []*nftables.Rule
		remove        bool
		kernelRules   []*nftables.Rule
		flushError    error
		expectedError string
		expectedRules []*nftables.Rule
	}{
		"add_success": {
			remove:        false,
			expectedRules: []*nftables.Rule{rule},
		},
		"add_flush_error": {
			remove:        false,
			flushError:    errors.New("flush failed"),
			expectedError: "flushing: flush failed",
		},
		"remove_success": {
			tracked:       []*nftables.Rule{rule},
			remove:        true,
			kernelRules:   []*nftables.Rule{{Table: table, Chain: chain, Handle: 42, Exprs: exprs}},
			expectedRules: []*nftables.Rule{},
		},
		"remove_not_tracked": {
			remove:        true,
			expectedError: "deleting rule: rule not found for removal",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{rules: testCase.tracked}

			if !testCase.remove {
				mockConn.EXPECT().AddRule(rule)
				mockConn.EXPECT().Flush().Return(testCase.flushError)
			} else {
				if len(testCase.tracked) > 0 {
					mockConn.EXPECT().GetRules(table, chain).Return(testCase.kernelRules, nil)
				}
				if testCase.expectedError == "" {
					mockConn.EXPECT().DelRule(gomock.Any())
					mockConn.EXPECT().Flush().Return(nil)
				}
			}

			err := f.addOrRemoveRule(mockConn, table, chain, exprs, testCase.remove)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedRules, f.rules)
		})
	}
}
