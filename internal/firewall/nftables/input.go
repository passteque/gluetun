package nftables

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (f *Firewall) AcceptInputThroughInterface(_ context.Context, intf string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, inputChain, _, _ := setupFilterWithBaseChains(conn)

	rule := &nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(intf + "\x00"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	conn.AddRule(rule)

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

// AcceptInputToPort accepts incoming traffic on the specified port, for both TCP and UDP
// protocols, on the interface intf. If intf is empty or "*", the interface is not used as a filter.
// If remove is true, the rule is removed instead of added. This is used for port forwarding, with
// intf set to the VPN tunnel interface.
func (f *Firewall) AcceptInputToPort(_ context.Context, intf string, port uint16, remove bool) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, inputChain, _, _ := setupFilterWithBaseChains(conn)
	portBytes := []byte{byte(port >> 8), byte(port)} //nolint:mnd,gosec // network byte order
	const tcp, udp uint8 = 6, 17
	protocols := []uint8{tcp, udp}

	for _, protocol := range protocols {
		const maxExprsLen = 7
		exprs := make([]expr.Any, 0, maxExprsLen)
		if intf != "" && intf != "*" {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
			)
		}
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, //nolint:mnd
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, //nolint:mnd
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)

		rule := &nftables.Rule{
			Table: table,
			Chain: inputChain,
			Exprs: exprs,
		}

		if !remove {
			conn.AddRule(rule)
			f.rules = append(f.rules, rule)
			continue
		}
		err = f.deleteRule(conn, rule)
		if err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
	}

	err = conn.Flush()
	if err != nil {
		f.rules = f.rules[:len(f.rules)-len(protocols)]
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}

func (f *Firewall) AcceptInputToSubnet(_ context.Context, intf string, subnet netip.Prefix) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, inputChain, _, _ := setupFilterWithBaseChains(conn)

	const maxExprsLen = 5
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	var payloadOffset uint32
	if subnet.Addr().Is4() {
		payloadOffset = 16
	} else {
		payloadOffset = 24
	}

	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       payloadOffset,
			Len:          uint32(len(subnet.Addr().AsSlice())), //nolint:gosec
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     subnet.Addr().AsSlice(),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	rule := &nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: exprs,
	}

	conn.AddRule(rule)

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing: %w", err)
	}

	return nil
}
