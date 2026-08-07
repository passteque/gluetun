package nftables

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
)

var ErrPolicyUnknown = errors.New("unknown policy")

// SetBaseChainsPolicy sets the policy of all the base chains (INPUT, FORWARD, or OUTPUT)
// for the filter table to the given policy (accept or drop).
func (f *Firewall) SetBaseChainsPolicy(_ context.Context, policy string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	var chainPolicy nftables.ChainPolicy
	switch strings.ToLower(policy) {
	case "accept":
		chainPolicy = nftables.ChainPolicyAccept
	case "drop":
		chainPolicy = nftables.ChainPolicyDrop
	default:
		return fmt.Errorf("%w: %s", ErrPolicyUnknown, policy)
	}

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	_, inputChain, forwardChain, outputChain := setupFilterWithBaseChains(conn)
	inputChain.Policy = &chainPolicy
	forwardChain.Policy = &chainPolicy
	outputChain.Policy = &chainPolicy

	conn.AddChain(inputChain)
	conn.AddChain(forwardChain)
	conn.AddChain(outputChain)

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing nftables changes: %w", err)
	}

	return nil
}

// SetIPv4AllPolicies sets the policy of all base chains to ACCEPT or DROP.
// In nftables with inet family, this also affects IPv6 rules.
func (f *Firewall) SetIPv4AllPolicies(ctx context.Context, policy string) error {
	return f.SetBaseChainsPolicy(ctx, policy)
}

// SetIPv6AllPolicies sets the policy of all base chains to ACCEPT or DROP.
// In nftables with inet family, this also affects IPv4 rules.
func (f *Firewall) SetIPv6AllPolicies(ctx context.Context, policy string) error {
	return f.SetBaseChainsPolicy(ctx, policy)
}
