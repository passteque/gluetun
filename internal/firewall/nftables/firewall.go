//go:build linux

package nftables

import (
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Firewall struct {
	runner   CmdRunner
	logger   Logger
	dialFunc dialFunc

	// rules are only rules added and tracked for later removal.
	// Not all rules added are tracked for removal.
	rules []*nftables.Rule
	mutex sync.Mutex
}

// New creates a new nftables-based Firewall.
func New(runner CmdRunner, logger Logger) *Firewall {
	return &Firewall{
		runner:   runner,
		logger:   logger,
		dialFunc: func() (conn, error) { return nftables.New() },
	}
}

// addOrRemoveRule adds or removes a rule with the given expressions on the
// given table and chain, tracking added rules for later removal.
func (f *Firewall) addOrRemoveRule(conn conn, table *nftables.Table, chain *nftables.Chain,
	exprs []expr.Any, remove bool,
) error {
	rule := &nftables.Rule{Table: table, Chain: chain, Exprs: exprs}

	if !remove {
		conn.AddRule(rule)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("flushing: %w", err)
		}
		f.rules = append(f.rules, rule)
		return nil
	}

	if err := f.deleteRule(conn, rule); err != nil {
		return fmt.Errorf("deleting rule: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing: %w", err)
	}
	f.untrackRule(rule)

	return nil
}
