//go:build linux

package nftables

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const preroutingChainName = "prerouting"

// getPreroutingChain returns the prerouting chain of the given table if it
// exists.
func getPreroutingChain(conn conn, table *nftables.Table) (*nftables.Chain, bool, error) {
	if table == nil {
		return nil, false, nil
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, false, fmt.Errorf("listing chains: %w", err)
	}
	for _, chain := range chains {
		if chain.Table.Family == table.Family && chain.Table.Name == table.Name &&
			chain.Name == preroutingChainName {
			return chain, true, nil
		}
	}
	return nil, false, nil
}

// newPreroutingChain returns a new prerouting chain definition for the given
// table.
func newPreroutingChain(table *nftables.Table) *nftables.Chain {
	return &nftables.Chain{
		Name:     preroutingChainName,
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	}
}

// RedirectPort redirects incoming traffic on the specified source port to the
// specified destination port, for both TCP and UDP protocols, on the interface
// intf. If intf is empty or "*", the interface is not used as a filter. If
// remove is true, the redirection is removed instead of added. This is used
// for VPN server side port forwarding, with intf set to the VPN tunnel
// interface.
func (f *Firewall) RedirectPort(_ context.Context, intf string,
	sourcePort, destinationPort uint16, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, inputChain, _, _, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	var preroutingChain *nftables.Chain
	if !remove {
		preroutingChain = conn.AddChain(newPreroutingChain(table))
	} else if preroutingChain, _, err = getPreroutingChain(conn, table); err != nil {
		return fmt.Errorf("listing prerouting chain: %w", err)
	}

	var addedRules []*nftables.Rule
	var deletedRules []*nftables.Rule
	for _, protocol := range [2]uint8{protocolTCP, protocolUDP} {
		prerouteRule := buildRedirectPrerouteRule(table, preroutingChain,
			intf, protocol, sourcePort, destinationPort)
		inputRule := buildRedirectInputRule(table, inputChain, intf, protocol, destinationPort)

		if !remove {
			conn.AddRule(prerouteRule)
			conn.AddRule(inputRule)
			addedRules = append(addedRules, prerouteRule, inputRule)
			continue
		}

		// The prerouting rule can only exist if the prerouting chain does.
		if preroutingChain != nil {
			if err := f.deleteRule(conn, prerouteRule); err != nil {
				return fmt.Errorf("deleting prerouting rule: %w", err)
			}
			deletedRules = append(deletedRules, prerouteRule)
		}
		if err := f.deleteRule(conn, inputRule); err != nil {
			return fmt.Errorf("deleting input rule: %w", err)
		}
		deletedRules = append(deletedRules, inputRule)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing nftables changes: %w", err)
	}

	if !remove {
		f.rules = append(f.rules, addedRules...)
	} else {
		for _, rule := range deletedRules {
			f.untrackRule(rule)
		}
	}

	return nil
}

// buildRedirectPrerouteRule builds the prerouting rule redirecting traffic
// arriving on the source port (matched as the destination port) to the
// destination port, the way `nft` compiles `dnat to :port`.
func buildRedirectPrerouteRule(table *nftables.Table, preroutingChain *nftables.Chain,
	intf string, protocol uint8, sourcePort, destinationPort uint16,
) *nftables.Rule {
	const register uint32 = 1
	destinationPortData := make([]byte, portLen)
	binary.BigEndian.PutUint16(destinationPortData, destinationPort)

	exprs := append(inputInterfaceExprs(intf), protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(sourcePort)...)
	exprs = append(exprs,
		&expr.Immediate{Register: register, Data: destinationPortData},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyINet),
			RegProtoMin: register,
			RegProtoMax: register,
			Specified:   true,
		},
	)

	return &nftables.Rule{Table: table, Chain: preroutingChain, Exprs: exprs}
}

// buildRedirectInputRule builds the input rule accepting traffic arriving on
// the redirected destination port.
func buildRedirectInputRule(table *nftables.Table, inputChain *nftables.Chain,
	intf string, protocol uint8, destinationPort uint16,
) *nftables.Rule {
	exprs := append(inputInterfaceExprs(intf), protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(destinationPort)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return &nftables.Rule{Table: table, Chain: inputChain, Exprs: exprs}
}
