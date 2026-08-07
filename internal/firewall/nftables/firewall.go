package nftables

import (
	"sync"

	"github.com/google/nftables"
)

type Firewall struct {
	logger Logger

	// rules are only rules added and tracked for later removal.
	// Not all rules added are tracked for removal.
	rules []*nftables.Rule
	mutex sync.Mutex
}

func New(logger Logger) *Firewall {
	return &Firewall{
		logger: logger,
	}
}
