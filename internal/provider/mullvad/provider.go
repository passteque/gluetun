package mullvad

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/mullvad/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher
}

func New(storage common.Storage, client *http.Client,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(client),
	}
}

func (p *Provider) Name() string {
	return providers.Mullvad
}
