package nftables

import "github.com/google/nftables"

func setupFilterWithBaseChains(conn *nftables.Conn) (table *nftables.Table,
	inputChain, forwardChain, outputChain *nftables.Chain,
) {
	table = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	inputChain = conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	forwardChain = conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	outputChain = conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
	})

	return table, inputChain, forwardChain, outputChain
}
