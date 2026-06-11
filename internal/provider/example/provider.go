package example

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/example/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher
}

// TODO: remove unneeded arguments once the updater is implemented.
func New(storage common.Storage, updaterWarner common.Warner, client *http.Client,
	unzipper common.Unzipper, parallelResolver common.ParallelResolver,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(updaterWarner, unzipper, client, parallelResolver),
	}
}

func (p *Provider) Name() string {
	// TODO: update the constant to be the right provider name.
	return providers.Example
}
