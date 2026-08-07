package nftables

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// TempDropOutputTCPRST temporarily drops outgoing TCP RST packets to the specified address and port,
// for any TCP packets not marked with the excludeMark given.
// This is necessary for TCP path MTU discovery to work, as the kernel will try to terminate the connection
// by sending a TCP RST packet, although we want to handle the connection manually.
func (f *Firewall) TempDropOutputTCPRST(_ context.Context,
	src, dst netip.AddrPort, excludeMark int,
) (revert func(ctx context.Context) error, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain := setupFilterWithBaseChains(conn)

	const maxExprsLen = 14
	exprs := make([]expr.Any, 0, maxExprsLen)

	// Match source IP
	if src.Addr().Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     src.Addr().AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     src.Addr().AsSlice(),
			},
		)
	}

	// Match destination IP
	if dst.Addr().Is4() {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, //nolint:mnd
				Len:          4,  //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dst.Addr().AsSlice(),
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, //nolint:mnd
				Len:          16, //nolint:mnd
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dst.Addr().AsSlice(),
			},
		)
	}

	// Match TCP protocol (6)
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
	)

	// Match source port
	srcPortBytes := []byte{byte(src.Port() >> 8), byte(src.Port())} //nolint:mnd,gosec // network byte order
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     srcPortBytes,
		},
	)

	// Match destination port
	dstPortBytes := []byte{byte(dst.Port() >> 8), byte(dst.Port())} //nolint:mnd,gosec // network byte order
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, //nolint:mnd
			Len:          2, //nolint:mnd
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     dstPortBytes,
		},
	)

	// Match TCP RST flag (only RST set)
	// TCP flags offset is 13th byte of the header (12 in 0-based)
	// RST flag is bit 1 (value 0x04)
	// We use bitwise to check mask == comparison (only RST is set)
	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13, //nolint:mnd
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x04},
		},
	)

	// Exclude packets with the mark using mark != excludeMark
	markData := []byte{ //nolint:gosec // mark is int (32-bit), byte conversions are intentional
		byte(excludeMark), byte(excludeMark >> 8), byte(excludeMark >> 16), byte(excludeMark >> 24), //nolint:mnd
	}
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     markData,
		},
	)

	// DROP verdict
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})

	rule := &nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: exprs,
	}

	conn.AddRule(rule)
	f.rules = append(f.rules, rule)

	err = conn.Flush()
	if err != nil {
		f.rules = f.rules[:len(f.rules)-1]
		return nil, fmt.Errorf("flushing: %w", err)
	}

	// Capture rule for revert
	ruleCopy := *rule

	revert = func(_ context.Context) error {
		f.mutex.Lock()
		defer f.mutex.Unlock()

		revertConn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("creating nftables connection for revert: %w", err)
		}

		err = f.deleteRule(revertConn, &ruleCopy)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}

		err = revertConn.Flush()
		if err != nil {
			return fmt.Errorf("flushing: %w", err)
		}

		return nil
	}

	return revert, nil
}
