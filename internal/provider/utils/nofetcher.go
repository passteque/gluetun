package utils

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/models"
)

type NoFetcher struct {
	providerName string
}

func NewNoFetcher(providerName string) *NoFetcher {
	return &NoFetcher{
		providerName: providerName,
	}
}

func (n *NoFetcher) FetchServers(context.Context, int) (
	servers []models.Server, err error,
) {
	return nil, fmt.Errorf("fetching of servers is not supported for %s", n.providerName)
}
