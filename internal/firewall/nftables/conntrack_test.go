//go:build linux

package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_AcceptEstablishedRelatedTraffic(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tables []*nftables.Table
		chains []*nftables.Chain
	}{
		"table_missing": {
			tables: nil,
			chains: nil,
		},
		"table_present": {
			tables: testGluetunTables(),
			chains: testBaseChainsAll(),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			mockConn.EXPECT().ListTables().Return(testCase.tables, nil)
			if len(testCase.tables) > 0 {
				mockConn.EXPECT().ListChains().Return(testCase.chains, nil)
			}
			if len(testCase.tables) == 0 {
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(3)
			}

			var addedRules []*nftables.Rule
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRules = append(addedRules, rule)
				return rule
			}).Times(2)
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptEstablishedRelatedTraffic(t.Context())

			assert.NoError(t, err)

			require.Len(t, addedRules, 2)
			// The same conntrack expressions are added to the input and
			// output chains.
			expectedExprs := establishedRelatedExprs()
			assert.Equal(t, expectedExprs, addedRules[0].Exprs)
			assert.Equal(t, expectedExprs, addedRules[1].Exprs)

			chains := map[string]bool{inputChainName: false, outputChainName: false}
			for _, rule := range addedRules {
				chains[rule.Chain.Name] = true
			}
			assert.Equal(t, map[string]bool{inputChainName: true, outputChainName: true}, chains)
		})
	}
}

// establishedRelatedExprs returns the expressions matching the nft CLI
// compilation of ct state established,related.
func establishedRelatedExprs() []expr.Any {
	const establishedRelatedMask = byte(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{establishedRelatedMask, 0x00, 0x00, 0x00},
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}
