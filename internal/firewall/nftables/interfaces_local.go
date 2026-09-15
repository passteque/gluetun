//go:build linux

package nftables

import "github.com/google/nftables"

type conn interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error)
	FlushChain(chain *nftables.Chain)
	AddTable(table *nftables.Table) *nftables.Table
	AddChain(chain *nftables.Chain) *nftables.Chain
	AddRule(rule *nftables.Rule) *nftables.Rule
	DelRule(rule *nftables.Rule) error
	DelTable(table *nftables.Table)
	Flush() error
}

type dialFunc func() (conn, error)
