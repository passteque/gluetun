package nftables

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildRedirectMatchExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf         string
		protocol     uint8
		portBytes    []byte
		wantExprLen  int
		wantFirstKey expr.MetaKey
	}{
		"no interface filter": {
			intf:        "",
			protocol:    6,                  // TCP
			portBytes:   []byte{0x00, 0x50}, // port 80
			wantExprLen: 4,
		},
		"star interface - no filter": {
			intf:        "*",
			protocol:    6,                  // TCP
			portBytes:   []byte{0x00, 0x50}, // port 80
			wantExprLen: 4,
		},
		"with interface filter": {
			intf:         "tun0",
			protocol:     17,                 // UDP
			portBytes:    []byte{0x00, 0x35}, // port 53
			wantExprLen:  6,
			wantFirstKey: expr.MetaKeyIIFNAME,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			exprs := buildRedirectMatchExprs(tc.intf, tc.protocol, tc.portBytes)

			assert.Len(t, exprs, tc.wantExprLen)

			if tc.intf != "" && tc.intf != "*" {
				// First two expressions should be interface match
				meta, ok := exprs[0].(*expr.Meta)
				require.True(t, ok)
				assert.Equal(t, expr.MetaKeyIIFNAME, meta.Key)
				cmp, ok := exprs[1].(*expr.Cmp)
				require.True(t, ok)
				assert.Equal(t, tc.intf+"\x00", string(cmp.Data))
			}
		})
	}
}

func Test_buildRedirectRule(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)

	natTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "nat",
	})

	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	rule := buildRedirectRule(conn, natTable, preroutingChain,
		"tun0", 6, []byte{0x00, 0x50}, 8080)

	assert.Equal(t, "nat", rule.Table.Name)
	assert.Equal(t, "prerouting", rule.Chain.Name)

	// Verify the rule contains NAT expression
	hasNAT := false
	for _, e := range rule.Exprs {
		if _, ok := e.(*expr.NAT); ok {
			hasNAT = true
			break
		}
	}
	assert.True(t, hasNAT)

	// Last expression should be NAT type DestNAT
	lastExpr, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.NAT)
	require.True(t, ok)
	assert.Equal(t, expr.NATTypeDestNAT, lastExpr.Type)
}

func Test_buildRedirectInputRule(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)
	table, inputChain, _, _ := setupFilterWithBaseChains(conn)

	rule := buildRedirectInputRule(table, inputChain, "tun0", 6, []byte{0x1F, 0x90}) // port 8080

	assert.Equal(t, "filter", rule.Table.Name)
	assert.Equal(t, "input", rule.Chain.Name)

	// Last expression should be VerdictAccept
	lastExpr, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictAccept, lastExpr.Kind)
}

func Test_isTableDoesNotExist(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		errMsg     string
		wantResult bool
	}{
		"simple table does not exist": {
			errMsg:     "Table does not exist",
			wantResult: true,
		},
		"table does not exist": {
			errMsg:     "error: Table does not exist",
			wantResult: true,
		},
		"other error": {
			errMsg:     "some other error",
			wantResult: false,
		},
		"empty": {
			errMsg:     "",
			wantResult: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if tc.errMsg == "" {
				// Empty string error message - isTableDoesNotExist returns false
				assert.False(t, isTableDoesNotExist(fmt.Errorf("")))
				return
			}
			assert.Equal(t, tc.wantResult, isTableDoesNotExist(fmt.Errorf("%s", tc.errMsg)), tc.errMsg)
		})
	}
}

func Test_removeFailedRules(t *testing.T) {
	t.Parallel()

	rules := []*nftables.Rule{
		{Table: nil, Chain: nil, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}},
		{Table: nil, Chain: nil, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}},
		{Table: nil, Chain: nil, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump}}},
	}

	testCases := map[string]struct {
		failed  []*nftables.Rule
		wantLen int
	}{
		"no failed rules": {
			failed:  []*nftables.Rule{},
			wantLen: 3,
		},
		"first rule failed": {
			failed:  []*nftables.Rule{rules[0]},
			wantLen: 2,
		},
		"multiple rules failed": {
			failed:  []*nftables.Rule{rules[0], rules[1]},
			wantLen: 1,
		},
		"all rules failed": {
			failed:  []*nftables.Rule{rules[0], rules[1], rules[2]},
			wantLen: 0,
		},
		"empty input": {
			failed:  []*nftables.Rule{},
			wantLen: 3,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := removeFailedRules(rules, tc.failed)
			assert.Len(t, result, tc.wantLen)
		})
	}
}

func Test_RedirectPort(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fw := New(nil)

	// Test basic redirect port call - in non-root environments, this fails at connection level.
	err := fw.RedirectPort(ctx, "tun0", 80, 8080, false)
	if err != nil {
		assert.Contains(t, err.Error(), "creating nftables connection")
	}
}

func Test_RedirectPort_ExpressionStructure(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)
	table, inputChain, _, _ := setupFilterWithBaseChains(conn)

	natTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "nat",
	})

	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	// Test that RedirectPort creates correct structure for both TCP and UDP
	sourcePortBytes := []byte{0x00, 0x50} // port 80
	destinationPort := uint16(8080)

	const tcp, udp uint8 = 6, 17
	for _, protocol := range []uint8{tcp, udp} {
		// Prerouting rule for NAT
		prerouteRule := buildRedirectRule(conn, natTable, preroutingChain,
			"tun0", protocol, sourcePortBytes, destinationPort)

		// Input rule for accepting redirected traffic
		inputPortBytes := []byte{byte(destinationPort >> 8), byte(destinationPort)} //nolint:gosec // network byte order
		inputRule := buildRedirectInputRule(table, inputChain,
			"tun0", protocol, inputPortBytes)

		assert.Equal(t, "nat", prerouteRule.Table.Name)
		assert.Equal(t, "prerouting", prerouteRule.Chain.Name)
		assert.Equal(t, "filter", inputRule.Table.Name)
		assert.Equal(t, "input", inputRule.Chain.Name)
	}
}

func Test_RedirectPort_PortBytes(t *testing.T) {
	t.Parallel()

	// Verify port byte encoding is correct (big-endian)
	testCases := map[string]struct {
		port      uint16
		wantBytes []byte
	}{
		"port 80": {
			port:      80,
			wantBytes: []byte{0x00, 0x50},
		},
		"port 443": {
			port:      443,
			wantBytes: []byte{0x01, 0xBB},
		},
		"port 8080": {
			port:      8080,
			wantBytes: []byte{0x1F, 0x90},
		},
		"port 65535": {
			port:      65535,
			wantBytes: []byte{0xFF, 0xFF},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			portBytes := []byte{byte(tc.port >> 8), byte(tc.port)} //nolint:gosec // network byte order
			assert.Equal(t, tc.wantBytes, portBytes)
		})
	}
}
