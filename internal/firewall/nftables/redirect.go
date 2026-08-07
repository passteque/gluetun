package nftables

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RedirectPort redirects incoming traffic on the specified source port to the
// specified destination port, for both TCP and UDP protocols, on the interface intf.
// If intf is empty or "*", the interface is not used as a filter. If remove is true,
// the redirection is removed instead of added. This is used for VPN server side
// port forwarding, with intf set to the VPN tunnel interface.
func (f *Firewall) RedirectPort(_ context.Context, intf string,
	sourcePort, destinationPort uint16, remove bool,
) (err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

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

	sourcePortBytes := []byte{byte(sourcePort >> 8), byte(sourcePort)}                //nolint:mnd,gosec
	destinationPortBytes := []byte{byte(destinationPort >> 8), byte(destinationPort)} //nolint:mnd,gosec
	const tcp, udp uint8 = 6, 17                                                      //nolint:mnd
	protocols := []uint8{tcp, udp}

	var rulesToDelete []*nftables.Rule

	for _, protocol := range protocols {
		prerouteRule := buildRedirectRule(conn, natTable, preroutingChain,
			intf, protocol, sourcePortBytes, destinationPort)

		if !remove {
			conn.AddRule(prerouteRule)
			f.rules = append(f.rules, prerouteRule)
		} else {
			err = f.deleteRule(conn, prerouteRule)
			if err != nil {
				rulesToDelete = append(rulesToDelete, prerouteRule)
			}
		}

		inputRule := buildRedirectInputRule(table, inputChain,
			intf, protocol, destinationPortBytes)

		if !remove {
			conn.AddRule(inputRule)
			f.rules = append(f.rules, inputRule)
		} else {
			err = f.deleteRule(conn, inputRule)
			if err != nil {
				rulesToDelete = append(rulesToDelete, inputRule)
			}
		}
	}

	err = conn.Flush()
	if err != nil && !isTableDoesNotExist(err) {
		if !remove {
			f.rules = removeFailedRules(f.rules, rulesToDelete)
		}
		return fmt.Errorf("redirecting source port %d to destination port %d on interface %s: %w",
			sourcePort, destinationPort, intf, err)
	}

	if isTableDoesNotExist(err) && !remove {
		f.logger.Warnf("IPv6 port redirection disabled because your kernel does not support IPv6 NAT: %s", err)
	}

	return nil
}

func buildRedirectRule(_ *nftables.Conn, natTable *nftables.Table,
	preroutingChain *nftables.Chain, intf string, protocol uint8,
	sourcePortBytes []byte, destinationPort uint16,
) *nftables.Rule {
	const regProto uint32 = 2
	portReg := make([]byte, regProto)
	binary.BigEndian.PutUint16(portReg, destinationPort)

	exprs := buildRedirectMatchExprs(intf, protocol, sourcePortBytes)
	exprs = append(exprs,
		&expr.Immediate{Register: regProto, Data: portReg},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyINet),
			RegProtoMin: regProto,
			RegProtoMax: regProto,
		},
	)

	return &nftables.Rule{
		Table: natTable,
		Chain: preroutingChain,
		Exprs: exprs,
	}
}

func buildRedirectInputRule(table *nftables.Table, inputChain *nftables.Chain,
	intf string, protocol uint8, destinationPortBytes []byte,
) *nftables.Rule {
	exprs := buildRedirectMatchExprs(intf, protocol, destinationPortBytes)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return &nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: exprs,
	}
}

func buildRedirectMatchExprs(intf string, protocol uint8, portBytes []byte) []expr.Any {
	const maxExprsLen = 6
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
	)

	return exprs
}

func isTableDoesNotExist(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Table does not exist")
}

func removeFailedRules(rules []*nftables.Rule, failed []*nftables.Rule) (succeeded []*nftables.Rule) {
	succeeded = make([]*nftables.Rule, 0, len(rules)-len(failed))
	for _, rule := range rules {
		if !slices.Contains(failed, rule) {
			succeeded = append(succeeded, rule)
		}
	}
	return succeeded
}
