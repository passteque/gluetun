package nftables

import (
	"context"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (f *Firewall) AcceptEstablishedRelatedTraffic(_ context.Context) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, inputChain, _, outputChain := setupFilterWithBaseChains(conn)

	ctStateExprs := []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4, //nolint:mnd
			Mask:           []byte{byte(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), 0x00, 0x00, 0x00},
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
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

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: ctStateExprs,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: ctStateExprs,
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}
