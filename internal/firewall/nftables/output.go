//go:build linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables/expr"
	"github.com/qdm12/gluetun/internal/models"
)

// errAddressFamiliesMismatch is returned when a method receives source and
// destination addresses of different address families, as the resulting rule
// could never match any packet.
var errAddressFamiliesMismatch = errors.New("source and destination address families do not match")

// AcceptIpv6MulticastOutput accepts outgoing traffic to the IPv6 multicast
// address ff02::1:ff00:0/104, which is used for NDP (Neighbor Discovery
// Protocol) to resolve the neighboring nodes, on the interface intf. If intf
// is empty or "*", the interface is not used as a filter.
func (f *Firewall) AcceptIpv6MulticastOutput(_ context.Context, intf string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	// ff02::1:ff00:0/104 is a subset of the solicited-node multicast space.
	const ipv6MulticastPrefix = "ff02::1:ff00:0/104"
	prefix := netip.MustParsePrefix(ipv6MulticastPrefix)

	exprs := append(outputInterfaceExprs(intf), destinationSubnetExprs(prefix)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, false)
}

// AcceptOutputTrafficToVPN accepts output traffic to the VPN connection IP and
// port, on the interface intf. If intf is empty or "*", the interface is not
// used as a filter. If remove is true, the rule is removed instead of added.
func (f *Firewall) AcceptOutputTrafficToVPN(_ context.Context, intf string,
	connection models.Connection, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	protocol, err := parseProtocol(connection.Protocol)
	if err != nil {
		return err
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(outputInterfaceExprs(intf), destinationIPExprs(connection.IP)...)
	exprs = append(exprs, protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(connection.Port)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, remove)
}

// AcceptOutput accepts output traffic to the given IP and port using the given
// protocol (tcp or udp), on the interface intf. If intf is empty or "*", the
// interface is not used as a filter. If remove is true, the rule is removed
// instead of added.
func (f *Firewall) AcceptOutput(_ context.Context, protocol, intf string,
	ip netip.Addr, port uint16, remove bool,
) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	protocolNumber, err := parseProtocol(protocol)
	if err != nil {
		return err
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(outputInterfaceExprs(intf), destinationIPExprs(ip)...)
	exprs = append(exprs, protocolExprs(protocolNumber)...)
	exprs = append(exprs, destinationPortExprs(port)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, remove)
}

// AcceptOutputFromIPPortToIPPort accepts output traffic from the given source
// IP and port to the given destination IP and port, using the given protocol
// (tcp or udp), on the interface intf. If intf is empty or "*", the interface
// is not used as a filter. If remove is true, the rule is removed instead of
// added.
func (f *Firewall) AcceptOutputFromIPPortToIPPort(_ context.Context, protocol, intf string,
	source, destination netip.AddrPort, remove bool,
) error {
	if source.Addr().BitLen() != destination.Addr().BitLen() {
		return errAddressFamiliesMismatch
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	protocolNumber, err := parseProtocol(protocol)
	if err != nil {
		return err
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(outputInterfaceExprs(intf), sourceIPExprs(source.Addr())...)
	exprs = append(exprs, destinationIPExprs(destination.Addr())...)
	exprs = append(exprs, protocolExprs(protocolNumber)...)
	exprs = append(exprs, sourcePortExprs(source.Port())...)
	exprs = append(exprs, destinationPortExprs(destination.Port())...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, remove)
}

// AcceptOutputFromIPToSubnet accepts output traffic from the given source IP
// to the given destination subnet, on the interface intf. If intf is empty or
// "*", the interface is not used as a filter. If remove is true, the rule is
// removed instead of added.
func (f *Firewall) AcceptOutputFromIPToSubnet(_ context.Context, intf string,
	assignedIP netip.Addr, subnet netip.Prefix, remove bool,
) error {
	if assignedIP.BitLen() != subnet.Addr().BitLen() {
		return errAddressFamiliesMismatch
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(outputInterfaceExprs(intf), sourceIPExprs(assignedIP)...)
	exprs = append(exprs, destinationSubnetExprs(subnet)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, remove)
}

// AcceptOutputThroughInterface accepts all output traffic through the given
// interface. If intf is empty or "*", the interface is not used as a filter.
// If remove is true, the rule is removed instead of added.
func (f *Firewall) AcceptOutputThroughInterface(_ context.Context, intf string, remove bool) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	table, _, _, outputChain, err := setupBaseChains(conn, nil)
	if err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	exprs := append(outputInterfaceExprs(intf), &expr.Verdict{Kind: expr.VerdictAccept})

	return f.addOrRemoveRule(conn, table, outputChain, exprs, remove)
}
