package nftables

import (
	"context"
	"fmt"

	"github.com/google/nftables"
)

// SaveAndRestore saves the current nftables tree and returns a restore function that
// can be called to restore the saved tree.
func (f *Firewall) SaveAndRestore(_ context.Context) (restore func(context.Context), err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}
	tables, err := saveTables(conn)
	if err != nil {
		return nil, fmt.Errorf("saving nftables state: %w", err)
	}
	return func(_ context.Context) {
		conn, err := nftables.New()
		if err != nil {
			f.logger.Warnf("creating nftables connection for restore: %s", err)
			return
		}
		err = restoreTables(conn, tables)
		if err != nil {
			f.logger.Warnf("restoring nftables state: %s", err)
		}
	}, nil
}

type savedTable struct {
	table  *nftables.Table
	chains []savedChain
}

type savedChain struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

func saveTables(conn *nftables.Conn) ([]savedTable, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}

	savedTables := make([]savedTable, len(tables))
	for i, table := range tables {
		savedTables[i].table = table

		chains, err := conn.ListChains()
		if err != nil {
			return nil, err
		}

		for _, chain := range chains {
			if chain.Table.Name != table.Name ||
				chain.Table.Family != table.Family {
				continue
			}
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				return nil, fmt.Errorf("getting rules for chain %s in table %s: %w", chain.Name, table.Name, err)
			}
			savedChain := savedChain{chain: chain, rules: rules}
			savedTables[i].chains = append(savedTables[i].chains, savedChain)
		}
	}

	return savedTables, nil
}

func restoreTables(conn *nftables.Conn, savedTables []savedTable) error {
	conn.FlushRuleset()

	for _, savedTable := range savedTables {
		table := conn.AddTable(savedTable.table)
		for _, savedChain := range savedTable.chains {
			// Make the [nftables.Chain.Table] points to the new [nftables.Table]
			// created in this connection.
			savedChain.chain.Table = table
			savedChain.chain = conn.AddChain(savedChain.chain)

			for _, rule := range savedChain.rules {
				rule.Table = table
				rule.Chain = savedChain.chain
				conn.AddRule(rule)
			}
		}
	}

	return conn.Flush()
}
