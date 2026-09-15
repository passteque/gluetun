//go:build linux

package nftables

import (
	"fmt"

	"github.com/google/nftables"
)

const (
	// gluetunTableName is the name of the inet table exclusively owned by
	// the nftables firewall backend. All its chains (input, forward, output,
	// prerouting) are created and deleted by the backend, so that
	// user-defined tables, chains, and rules are never modified.
	gluetunTableName = "gluetun"
	inputChainName   = "input"
	forwardChainName = "forward"
	outputChainName  = "output"
)

// getGluetunTable returns the backend-owned inet table if it exists.
func getGluetunTable(conn conn) (*nftables.Table, bool, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, false, fmt.Errorf("listing tables: %w", err)
	}
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet && table.Name == gluetunTableName {
			return table, true, nil
		}
	}
	return nil, false, nil
}

// setupBaseChains ensures that the backend-owned table and its three base
// filter chains (input, forward, output) exist, returning them.
// If policy is non-nil, it is applied to each of the base chains, existing or
// newly created.
func setupBaseChains(conn conn, policy *nftables.ChainPolicy) (table *nftables.Table,
	inputChain, forwardChain, outputChain *nftables.Chain,
	err error,
) {
	table, found, err := getGluetunTable(conn)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !found {
		table = conn.AddTable(&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   gluetunTableName,
		})
	}

	existingChains := make(map[string]*nftables.Chain)
	if found {
		chains, err := conn.ListChains()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("listing chains: %w", err)
		}
		for _, chain := range chains {
			if chain.Table.Family == table.Family && chain.Table.Name == table.Name {
				existingChains[chain.Name] = chain
			}
		}
	}

	ensureChain := func(name string, hooknum *nftables.ChainHook) *nftables.Chain {
		if chain, ok := existingChains[name]; ok {
			if policy != nil {
				chain.Policy = policy
				conn.AddChain(chain)
			}
			return chain
		}
		return conn.AddChain(&nftables.Chain{
			Name:     name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  hooknum,
			Priority: nftables.ChainPriorityFilter,
			Policy:   policy,
		})
	}

	inputChain = ensureChain(inputChainName, nftables.ChainHookInput)
	forwardChain = ensureChain(forwardChainName, nftables.ChainHookForward)
	outputChain = ensureChain(outputChainName, nftables.ChainHookOutput)

	return table, inputChain, forwardChain, outputChain, nil
}
