package purevpn

import (
	"math/rand"
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/purevpn/updater"
)

type Provider struct {
	storage    common.Storage
	randSource rand.Source
	common.Fetcher
}

func New(storage common.Storage, randSource rand.Source, client *http.Client,
	updaterWarner common.Warner, parallelResolver common.ParallelResolver,
) *Provider {
	return &Provider{
		storage:    storage,
		randSource: randSource,
		Fetcher:    updater.New(client, updaterWarner, parallelResolver),
	}
}

func (p *Provider) Name() string {
	return providers.Purevpn
}
