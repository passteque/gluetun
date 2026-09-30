//go:build linux

package nftables

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// TempDropOutputTCPRST temporarily drops outgoing TCP RST packets from the
// given source IP and port to the given destination IP and port, for packets
// not marked with the excludeMark given.
// This is necessary for TCP path MTU discovery to work, as the kernel will try
// to terminate the connection by sending a TCP RST packet, although we want to
// handle the connection manually.
// A revert function is returned, which must be called to remove the rule.
func (f *Firewall) TempDropOutputTCPRST(_ context.Context,
	src, dst netip.AddrPort, excludeMark int,
) (revert func(ctx context.Context) error, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Netfilter marks are 32-bit values.
	if excludeMark < 0 || uint64(excludeMark) > math.MaxUint32 {
		return nil, fmt.Errorf("exclude mark out of range: %d", excludeMark)
	}

	conn, err := f.dialFunc()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return nil, fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(sourceIPExprs(src.Addr()), destinationIPExprs(dst.Addr())...)
	exprs = append(exprs, protocolExprs(protocolTCP)...)
	exprs = append(exprs, sourcePortExprs(src.Port())...)
	exprs = append(exprs, destinationPortExprs(dst.Port())...)

	// Match TCP packets with the RST flag set, the way the nft CLI compiles
	// --tcp-flags RST RST: mask the RST bit (0x04) of the flags byte, then
	// require the masked value to be RST.
	const tcpFlagsOffset = 13
	const tcpRSTFlag = 0x04
	exprs = append(exprs,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: tcpFlagsOffset, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{tcpRSTFlag}, Xor: []byte{0x00}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tcpRSTFlag}},
	)

	// Exclude packets marked with the given mark. The mark is a little-endian
	// 32-bit value.
	const markLen = 4
	markData := make([]byte, markLen)
	binary.LittleEndian.PutUint32(markData, uint32(excludeMark))
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: markData},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)

	rule := &nftables.Rule{Table: table, Chain: outputChain, Exprs: exprs}

	conn.AddRule(rule)
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("flushing: %w", err)
	}
	f.rules = append(f.rules, rule)

	revert = func(_ context.Context) error {
		f.mutex.Lock()
		defer f.mutex.Unlock()

		revertConn, err := f.dialFunc()
		if err != nil {
			return fmt.Errorf("creating nftables connection for revert: %w", err)
		}

		if err := f.deleteRule(revertConn, rule); err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}

		if err := revertConn.Flush(); err != nil {
			return fmt.Errorf("flushing: %w", err)
		}
		f.untrackRule(rule)

		return nil
	}

	return revert, nil
}
