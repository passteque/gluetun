package perfectprivacy

import (
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/perfectprivacy/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher
}

func New(storage common.Storage, unzipper common.Unzipper, updaterWarner common.Warner,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(unzipper, updaterWarner),
	}
}

func (p *Provider) Name() string {
	return providers.Perfectprivacy
}
