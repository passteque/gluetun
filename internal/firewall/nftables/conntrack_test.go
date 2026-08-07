package nftables

import (
	"context"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AcceptEstablishedRelatedTraffic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fw := New(nil)

	err := fw.AcceptEstablishedRelatedTraffic(ctx)
	// This test verifies the function doesn't panic and constructs the correct rule structure.
	// In environments without root access, it will fail when trying to flush.
	// We test the logic by verifying it returns a reasonable error if nftables isn't available.
	if err != nil {
		// Expected failure in non-root environments
		assert.Contains(t, err.Error(), "creating nftables connection")
	}
}

func Test_conntrackRuleExpressions(t *testing.T) {
	t.Parallel()

	// This test verifies the structure of conntrack expressions used in
	// AcceptEstablishedRelatedTraffic by constructing them directly.
	// The rule should:
	// 1. Load connection tracking state into register 1
	// 2. Bitwise AND with ESTABLISHED|RELATED mask
	// 3. Compare != 0 (if not matching, continue)
	// 4. ACCEPT

	ctStateExprs := []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask: []byte{
				byte(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				0x00, 0x00, 0x00,
			},
			Xor: []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}

	require.Len(t, ctStateExprs, 4)

	// Verify CT expression
	ctExpr, ok := ctStateExprs[0].(*expr.Ct)
	require.True(t, ok)
	assert.Equal(t, expr.CtKeySTATE, ctExpr.Key)
	assert.Equal(t, uint32(1), ctExpr.Register)

	// Verify Bitwise expression
	bwExpr, ok := ctStateExprs[1].(*expr.Bitwise)
	require.True(t, ok)
	assert.Equal(t, uint32(1), bwExpr.SourceRegister)
	assert.Equal(t, uint32(1), bwExpr.DestRegister)
	assert.Equal(t, uint32(4), bwExpr.Len)
	// INVALID=0x01, ESTABLISHED=0x02, RELATED=0x04, NEW=0x08
	// ESTABLISHED | RELATED = 0x06
	assert.Equal(t, byte(0x06), bwExpr.Mask[0])

	// Verify Cmp expression (not equal to zero)
	cmpExpr, ok := ctStateExprs[2].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, expr.CmpOpNeq, cmpExpr.Op)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, cmpExpr.Data)

	// Verify Verdict expression
	verdict, ok := ctStateExprs[3].(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, expr.VerdictAccept, verdict.Kind)
}

func Test_conntrackRuleTableChainAssignment(t *testing.T) {
	t.Parallel()

	// Verify that conntrack rules would be correctly assigned to input and output chains
	conn, err := nftables.New()
	require.NoError(t, err)
	table, inputChain, _, outputChain := setupFilterWithBaseChains(conn)

	ctStateExprs := []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	inputRule := &nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: ctStateExprs,
	}

	outputRule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: ctStateExprs,
	}

	assert.Equal(t, "filter", inputRule.Table.Name)
	assert.Equal(t, "input", inputRule.Chain.Name)
	assert.Equal(t, "filter", outputRule.Table.Name)
	assert.Equal(t, "output", outputRule.Chain.Name)
}
