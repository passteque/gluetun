package cryptostorm

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/cryptostorm/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage         common.Storage
	connPicker      *utils.ConnectionPicker
	portForwardPath string
	forwardedPort   uint16 // set after a successful PortForward, used for teardown
	common.Fetcher
}

func New(storage common.Storage, client *http.Client) *Provider {
	const jsonPortForwardPath = "/gluetun/portforward/cryptostorm.json"
	return &Provider{
		storage:         storage,
		connPicker:      utils.NewConnectionPicker(),
		portForwardPath: jsonPortForwardPath,
		Fetcher:         updater.New(client),
	}
}

func (p *Provider) Name() string {
	return providers.Cryptostorm
}
