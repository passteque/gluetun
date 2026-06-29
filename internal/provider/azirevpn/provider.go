package azirevpn

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/azirevpn/updater"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	common.Fetcher

	client *http.Client
	token  string

	dataPath string
}

func New(storage common.Storage, client *http.Client,
	updaterWarner common.Warner, token string,
) *Provider {
	const jsonDataPath = "/tmp/gluetun/azirevpn_data.json"
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		Fetcher:    updater.New(client, updaterWarner, token),
		client:     client,
		token:      token,
		dataPath:   jsonDataPath,
	}
}

func (p *Provider) Name() string {
	return providers.Azirevpn
}
