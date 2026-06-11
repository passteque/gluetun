package protonvpn

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/protonvpn/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher
	internalToExternalPorts map[uint16]uint16
}

func New(storage common.Storage, client *http.Client, updaterWarner common.Warner,
	email, password string,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(client, updaterWarner, email, password),
	}
}

func (p *Provider) Name() string {
	return providers.Protonvpn
}
