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

// AcceptIpv6MulticastInput accepts incoming traffic from the IPv6 multicast
// address ff02::1:ff00:0/104, which is used for NDP (Neighbor Discovery
// Protocol) to resolve the neighboring nodes, on the interface intf. This
// notably allows the neighbor solicitation packets sent by other nodes to
// reach Gluetun, so that they can resolve its MAC address and reach it.
// If intf is empty or "*", the interface is not used as a filter.
func (f *Firewall) AcceptIpv6MulticastInput(_ context.Context, intf string) error {
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

	// ff02::1:ff00:0/104 is a subset of the solicited-node multicast space.
	const ipv6MulticastPrefix = "ff02::1:ff00:0/104"
	prefix := netip.MustParsePrefix(ipv6MulticastPrefix)

	exprs := append(inputInterfaceExprs(intf), destinationSubnetExprs(prefix)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, inputChain, exprs, false)
}
