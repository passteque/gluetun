//go:build linux

package nftables

import (
	"context"
	"fmt"

	"github.com/google/nftables"
)

// SaveAndRestore saves the current nftables state and the tracked rules, and
// returns a restore function that can be called to restore the saved state.
func (f *Firewall) SaveAndRestore(_ context.Context) (func(context.Context), error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	// The owned table can only exist if a previous session did not restore
	// it (for example a crash), so it is stale by definition and must be
	// removed before the save, otherwise the restore would resurrect it.
	if err := f.removeStaleOwnedTable(conn); err != nil {
		return nil, fmt.Errorf("removing stale %s table: %w", gluetunTableName, err)
	}

	innerRestore, err := f.saveAndRestoreLocked(conn)
	if err != nil {
		return nil, err
	}

	// The caller of the returned restore function does not hold the mutex.
	return func(ctx context.Context) {
		f.mutex.Lock()
		defer f.mutex.Unlock()

		innerRestore(ctx)
	}, nil
}

// saveAndRestoreLocked saves the current nftables state and the tracked rules,
// and returns a restore function that restores both. Callers MUST hold the
// mutex, and the returned restore function requires it to be held as well.
func (f *Firewall) saveAndRestoreLocked(conn conn) (restore func(context.Context), err error) {
	savedTables, err := saveTables(conn)
	if err != nil {
		return nil, fmt.Errorf("saving nftables state: %w", err)
	}

	// Snapshot the tracked rules so that the restore can return the tracker to
	// the saved state, avoiding stale or duplicated tracking across
	// disable/enable cycles.
	savedRules := make([]*nftables.Rule, len(f.rules))
	copy(savedRules, f.rules)

	return func(ctx context.Context) {
		f.restoreStateLocked(ctx, savedTables, savedRules)
	}, nil
}

// removeStaleOwnedTable removes the backend-owned table if it exists.
func (f *Firewall) removeStaleOwnedTable(conn conn) error {
	table, found, err := getGluetunTable(conn)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	conn.DelTable(table)
	return conn.Flush()
}

// restoreStateLocked restores the saved nftables state and tracked rules,
// logging a warning on failure. Callers MUST hold the mutex.
func (f *Firewall) restoreStateLocked(_ context.Context, tables []savedTable, rules []*nftables.Rule) {
	conn, err := f.dialFunc()
	if err != nil {
		f.logger.Warnf("creating nftables connection for restore: %s", err)
	} else if err := restoreTables(conn, tables); err != nil {
		f.logger.Warnf("restoring nftables state: %s", err)
	}

	// Reset the tracker to the saved state, so that rules added by the session
	// are not tracked (and later removed as duplicates) after the restore.
	f.rules = rules
}

type tableKey struct {
	family nftables.TableFamily
	name   string
}

type savedTable struct {
	table  *nftables.Table
	chains []savedChain
}

type savedChain struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

// saveTables saves the state of all the tables, their chains, and their rules.
func saveTables(conn conn) ([]savedTable, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("listing chains: %w", err)
	}

	chainsByTable := make(map[tableKey][]*nftables.Chain, len(tables))
	for _, chain := range chains {
		key := tableKey{family: chain.Table.Family, name: chain.Table.Name}
		chainsByTable[key] = append(chainsByTable[key], chain)
	}

	savedTables := make([]savedTable, 0, len(tables))
	for _, table := range tables {
		savedTable := savedTable{table: table}
		key := tableKey{family: table.Family, name: table.Name}
		for _, chain := range chainsByTable[key] {
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				return nil, fmt.Errorf("getting rules for chain %s in table %s: %w",
					chain.Name, table.Name, err)
			}
			savedTable.chains = append(savedTable.chains, savedChain{chain: chain, rules: rules})
		}
		savedTables = append(savedTables, savedTable)
	}

	return savedTables, nil
}

// restoreTables restores the saved nftables state: tables created after the
// save are removed (the backend only creates its owned table, and user post
// rules are re-run at the next enable), then each saved chain is flushed and
// its saved rules re-added, the way iptables-restore does, while other
// pre-existing state is left untouched.
func restoreTables(conn conn, savedTables []savedTable) error {
	savedTableKeys := make(map[tableKey]struct{}, len(savedTables))
	for _, savedTable := range savedTables {
		savedTableKeys[tableKey{family: savedTable.table.Family, name: savedTable.table.Name}] = struct{}{}
	}

	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	for _, table := range tables {
		key := tableKey{family: table.Family, name: table.Name}
		if _, saved := savedTableKeys[key]; saved {
			continue
		}
		conn.DelTable(table)
	}

	for _, savedTable := range savedTables {
		table := conn.AddTable(savedTable.table)
		for _, savedChain := range savedTable.chains {
			// Make a copy so that the saved state is not mutated, allowing the
			// restore to be called multiple times.
			chain := *savedChain.chain
			chain.Table = table
			restoredChain := conn.AddChain(&chain)
			conn.FlushChain(restoredChain)

			for _, rule := range savedChain.rules {
				ruleCopy := *rule
				ruleCopy.Handle = 0 // append, not replace at the saved handle
				ruleCopy.Table = table
				ruleCopy.Chain = restoredChain
				conn.AddRule(&ruleCopy)
			}
		}
	}

	return conn.Flush()
}
