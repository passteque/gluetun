package vyprvpn

import (
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/qdm12/gluetun/internal/provider/vyprvpn/updater"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher
}

func New(storage common.Storage, unzipper common.Unzipper, updaterWarner common.Warner,
	parallelResolver common.ParallelResolver,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(unzipper, updaterWarner, parallelResolver),
	}
}

func (p *Provider) Name() string {
	return providers.Vyprvpn
}
