//go:build linux

package nftables

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// expectedRSTExprs mirrors the production composition for
// TempDropOutputTCPRST, matching the nft CLI compilation of
// `ip saddr ... ip daddr ... tcp sport ... tcp dport ... tcp flags & rst == rst
// meta mark != <mark> drop`.
func expectedRSTExprs(src, dst netip.AddrPort, excludeMark int) []expr.Any {
	exprs := append(sourceIPExprs(src.Addr()), destinationIPExprs(dst.Addr())...)
	exprs = append(exprs, protocolExprs(protocolTCP)...)
	exprs = append(exprs, sourcePortExprs(src.Port())...)
	exprs = append(exprs, destinationPortExprs(dst.Port())...)

	const tcpFlagsOffset, tcpRSTFlag = 13, 0x04
	exprs = append(exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: tcpFlagsOffset, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{tcpRSTFlag}, Xor: []byte{0x00}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tcpRSTFlag}},
	)

	markData := make([]byte, 4)
	binary.LittleEndian.PutUint32(markData, uint32(excludeMark)) //nolint:gosec // test uses a fixed in-range mark
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: markData},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
	return exprs
}

func Test_TempDropOutputTCPRST_add(t *testing.T) {
	t.Parallel()

	src := netip.MustParseAddrPort("10.8.0.2:44444")
	dst := netip.MustParseAddrPort("10.8.0.1:51820")
	excludeMark := 0x1234

	testCases := map[string]struct {
		flushError    error
		expectedError string
	}{
		"success": {},
		"flush_error": {
			flushError:    errors.New("flush failed"),
			expectedError: "flushing: flush failed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			expectNewGluetunTable(mockConn)

			var addedRule *nftables.Rule
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRule = rule
				return rule
			})
			mockConn.EXPECT().Flush().Return(testCase.flushError)

			revert, err := f.TempDropOutputTCPRST(t.Context(), src, dst, excludeMark)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				assert.Nil(t, revert)
				assert.Empty(t, f.rules)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, revert)
			assert.NotNil(t, addedRule)
			assert.Equal(t, outputChainName, addedRule.Chain.Name)
			assert.Equal(t, expectedRSTExprs(src, dst, excludeMark), addedRule.Exprs)
			assert.Len(t, f.rules, 1)
		})
	}
}

// Test_TempDropOutputTCPRST_revert adds the rule and then exercises the
// returned revert function. The add and revert phases share a single mock
// connection, so the expectations are set in call order.
func Test_TempDropOutputTCPRST_revert(t *testing.T) {
	t.Parallel()

	src := netip.MustParseAddrPort("10.8.0.2:44444")
	dst := netip.MustParseAddrPort("10.8.0.1:51820")
	excludeMark := 0x1234
	expectedExprs := expectedRSTExprs(src, dst, excludeMark)

	testCases := map[string]struct {
		delRuleError  error
		flushError    error
		revertTwice   bool
		expectedError string
	}{
		"success": {},
		"del_rule_error": {
			delRuleError:  errors.New("del failed"),
			expectedError: "deleting rule: del failed",
		},
		"flush_error": {
			flushError:    errors.New("flush failed"),
			expectedError: "flushing: flush failed",
		},
		"revert_twice_second_fails": {
			revertTwice:   true,
			expectedError: "deleting rule: rule not found for removal",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			// Add phase: create the filter table and the RST rule.
			expectNewGluetunTable(mockConn)
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				return rule
			})
			mockConn.EXPECT().Flush().Return(nil) // add phase flush

			// Revert phase: delete the rule.
			mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
				[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
			)
			mockConn.EXPECT().DelRule(gomock.Any()).Return(testCase.delRuleError)
			if testCase.delRuleError == nil {
				mockConn.EXPECT().Flush().Return(testCase.flushError) // revert phase flush
			}

			revert, err := f.TempDropOutputTCPRST(t.Context(), src, dst, excludeMark)
			require.NoError(t, err)
			require.NotNil(t, revert)

			revertErr := revert(t.Context())

			if testCase.revertTwice {
				// The first revert succeeded; the second must fail (untracked).
				assert.NoError(t, revertErr)
				revertErr = revert(t.Context())
			}

			if testCase.expectedError != "" {
				assert.ErrorContains(t, revertErr, testCase.expectedError)
				return
			}
			assert.NoError(t, revertErr)
			assert.Empty(t, f.rules)
		})
	}
}
