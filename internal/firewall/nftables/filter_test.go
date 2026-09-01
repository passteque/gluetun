//go:build linux

package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func testBaseChains() (inputChain, forwardChain, outputChain *nftables.Chain) {
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	return &nftables.Chain{
			Name: inputChainName, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
		}, &nftables.Chain{
			Name: forwardChainName, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
		}, &nftables.Chain{
			Name: outputChainName, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
		}
}

func Test_setupBaseChains(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tables   []*nftables.Table
		chains   []*nftables.Chain
		policy   *nftables.ChainPolicy
		addTable bool
		addChain int
	}{
		"table_and_chains_missing": {
			tables:   nil,
			chains:   nil,
			policy:   nil,
			addTable: true,
			addChain: 3,
		},
		"table_missing_chains_present_but_table_missing": {
			tables:   nil,
			chains:   testBaseChainsAll(),
			policy:   nil,
			addTable: true,
			addChain: 3,
		},
		"table_present_chains_missing": {
			tables:   testGluetunTables(),
			chains:   nil,
			policy:   nil,
			addTable: false,
			addChain: 3,
		},
		"table_and_chains_present_no_policy": {
			tables:   testGluetunTables(),
			chains:   testBaseChainsAll(),
			policy:   nil,
			addTable: false,
			addChain: 0,
		},
		"table_and_chains_present_with_policy": {
			tables:   testGluetunTables(),
			chains:   testBaseChainsAll(),
			policy:   testPolicyDrop(),
			addTable: false,
			addChain: 3,
		},
		"table_and_chains_missing_with_policy": {
			tables:   nil,
			chains:   nil,
			policy:   testPolicyDrop(),
			addTable: true,
			addChain: 3,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)

			mockConn.EXPECT().ListTables().Return(testCase.tables, nil)
			if len(testCase.tables) > 0 {
				mockConn.EXPECT().ListChains().Return(testCase.chains, nil)
			}
			if testCase.addTable {
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				}).Times(1)
			}
			mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
				return chain
			}).Times(testCase.addChain)

			resultTable, resultInputChain, resultForwardChain, resultOutputChain, err := setupBaseChains(
				mockConn, testCase.policy,
			)

			assert.NoError(t, err)

			assert.Equal(t, gluetunTableName, resultTable.Name)
			assert.Equal(t, nftables.TableFamilyINet, resultTable.Family)

			assertChain(t, resultInputChain, "input", nftables.ChainHookInput, testCase.policy)
			assertChain(t, resultForwardChain, "forward", nftables.ChainHookForward, testCase.policy)
			assertChain(t, resultOutputChain, "output", nftables.ChainHookOutput, testCase.policy)
		})
	}
}

func assertChain(t *testing.T, chain *nftables.Chain, name string,
	hook *nftables.ChainHook, policy *nftables.ChainPolicy,
) {
	t.Helper()
	assert.NotNil(t, chain)
	assert.Equal(t, name, chain.Name)
	assert.Equal(t, nftables.ChainTypeFilter, chain.Type)
	assert.Equal(t, hook, chain.Hooknum)
	if policy == nil {
		assert.Nil(t, chain.Policy)
	} else {
		assert.Equal(t, policy, chain.Policy)
	}
}

func testGluetunTables() []*nftables.Table {
	return []*nftables.Table{{Family: nftables.TableFamilyINet, Name: gluetunTableName}}
}

func testBaseChainsAll() []*nftables.Chain {
	inputChain, forwardChain, outputChain := testBaseChains()
	return []*nftables.Chain{inputChain, forwardChain, outputChain}
}

func testPolicyDrop() *nftables.ChainPolicy {
	chainPolicy := nftables.ChainPolicyDrop
	return &chainPolicy
}
