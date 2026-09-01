//go:build linux

package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_parseChainPolicy(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		policy        string
		expected      *nftables.ChainPolicy
		expectedError string
	}{
		"accept": {
			policy:   "accept",
			expected: testPolicyAccept(),
		},
		"accept_upper": {
			policy:   "ACCEPT",
			expected: testPolicyAccept(),
		},
		"drop": {
			policy:   "drop",
			expected: testPolicyDrop(),
		},
		"drop_mixed_case": {
			policy:   "DrOp",
			expected: testPolicyDrop(),
		},
		"unknown": {
			policy:        "foo",
			expectedError: "unknown policy: foo",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chainPolicy, err := parseChainPolicy(testCase.policy)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				assert.Nil(t, chainPolicy)
				return
			}

			assert.NoError(t, err)
			require.NotNil(t, chainPolicy)
			assert.Equal(t, *testCase.expected, *chainPolicy)
		})
	}
}

func Test_SetBaseChainsPolicy(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		policy        string
		tables        []*nftables.Table
		chains        []*nftables.Chain
		addTable      bool
		addChain      int
		expectedError string
	}{
		"accept_new": {
			policy:   "accept",
			addTable: true,
			addChain: 3,
		},
		"drop_new": {
			policy:   "drop",
			addTable: true,
			addChain: 3,
		},
		"accept_existing": {
			policy:   "accept",
			tables:   testGluetunTables(),
			chains:   testBaseChainsAll(),
			addChain: 3,
		},
		"drop_existing": {
			policy:   "drop",
			tables:   testGluetunTables(),
			chains:   testBaseChainsAll(),
			addChain: 3,
		},
		"unknown_policy": {
			policy:        "foo",
			expectedError: "unknown policy: foo",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			if testCase.expectedError == "" {
				mockConn.EXPECT().ListTables().Return(testCase.tables, nil)
				if len(testCase.tables) > 0 {
					mockConn.EXPECT().ListChains().Return(testCase.chains, nil)
				}
				if testCase.addTable {
					mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
						return table
					})
				}
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(testCase.addChain)
				mockConn.EXPECT().Flush().Return(nil)
			}

			err := f.SetBaseChainsPolicy(t.Context(), testCase.policy)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func testPolicyAccept() *nftables.ChainPolicy {
	chainPolicy := nftables.ChainPolicyAccept
	return &chainPolicy
}
