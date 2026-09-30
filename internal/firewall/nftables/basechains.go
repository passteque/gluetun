//go:build linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
)

var ErrPolicyUnknown = errors.New("unknown policy")

// SetBaseChainsPolicy sets the policy of all the base chains (input, forward,
// output) of the backend-owned table to the given policy (accept or drop).
func (f *Firewall) SetBaseChainsPolicy(_ context.Context, policy string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	chainPolicy, err := parseChainPolicy(policy)
	if err != nil {
		return err
	}

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	if _, _, _, _, err = setupBaseChains(conn, chainPolicy); err != nil {
		return fmt.Errorf("setting up base chains: %w", err)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing nftables changes: %w", err)
	}

	return nil
}

func parseChainPolicy(policy string) (*nftables.ChainPolicy, error) {
	switch strings.ToLower(policy) {
	case "accept":
		chainPolicy := nftables.ChainPolicyAccept
		return &chainPolicy, nil
	case "drop":
		chainPolicy := nftables.ChainPolicyDrop
		return &chainPolicy, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrPolicyUnknown, policy)
	}
}
