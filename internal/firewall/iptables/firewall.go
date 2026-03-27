package iptables

import (
	"context"
	"sync"
)

type Config struct {
	runner        CmdRunner
	logger        Logger
	iptablesMutex sync.Mutex

	// Fixed state
	ipTables  string
	ip6Tables string
}

func New(ctx context.Context, runner CmdRunner, logger Logger) (*Config, error) {
	iptables, err := checkIptablesSupport(ctx, runner, "iptables", "iptables-nft", "iptables-legacy")
	if err != nil {
		return nil, err
	}

	ip6tables, err := findIP6tablesSupported(ctx, runner)
	if err != nil {
		return nil, err
	}

	return &Config{
		runner:    runner,
		logger:    logger,
		ipTables:  iptables,
		ip6Tables: ip6tables,
	}, nil
}
