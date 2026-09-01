//go:build linux

package nftables

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// AcceptInputThroughInterface accepts all input traffic coming through the
// given interface.
func (f *Firewall) AcceptInputThroughInterface(_ context.Context, intf string) error {
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

	exprs := append(inputInterfaceExprs(intf), &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, inputChain, exprs, false)
}

// AcceptInputToPort accepts incoming traffic on the specified port, for both
// TCP and UDP protocols, on the interface intf. If intf is empty or "*", the
// interface is not used as a filter. If remove is true, the rules are removed
// instead of added. This is used for port forwarding, with intf set to the VPN
// tunnel interface.
func (f *Firewall) AcceptInputToPort(_ context.Context, intf string, port uint16, remove bool) error {
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

	var addedRules []*nftables.Rule
	var deletedRules []*nftables.Rule
	for _, protocol := range [2]uint8{protocolTCP, protocolUDP} {
		exprs := append(inputInterfaceExprs(intf), protocolExprs(protocol)...)
		exprs = append(exprs, destinationPortExprs(port)...)
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

		rule := &nftables.Rule{Table: table, Chain: inputChain, Exprs: exprs}

		if !remove {
			conn.AddRule(rule)
			addedRules = append(addedRules, rule)
			continue
		}

		if err := f.deleteRule(conn, rule); err != nil {
			return fmt.Errorf("deleting rule: %w", err)
		}
		deletedRules = append(deletedRules, rule)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
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

// AcceptInputToSubnet accepts incoming traffic whose destination is the given
// subnet, on the interface intf. If intf is empty or "*", the interface is
// not used as a filter.
func (f *Firewall) AcceptInputToSubnet(_ context.Context, intf string, subnet netip.Prefix) error {
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

	exprs := append(inputInterfaceExprs(intf), destinationSubnetExprs(subnet)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, inputChain, exprs, false)
}
