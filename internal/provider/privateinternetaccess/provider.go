package privateinternetaccess

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage         common.Storage
	connPicker      *utils.ConnectionPicker
	timeNow         func() time.Time
	common.Fetcher
	// Port forwarding
	portForwardPath string
	apiIP           netip.Addr
	client          *http.Client
	addWireguardKey func(ctx context.Context, serverName string, serverIP netip.Addr,
		token, publicKey string) (result addKeyResult, err error)
	fetchAuthToken  func(ctx context.Context, serverName string, serverIP netip.Addr,
		username, password string) (token string, err error)
}

func New(storage common.Storage, timeNow func() time.Time,
	client *http.Client,
) *Provider {
	const jsonPortForwardPath = "/gluetun/piaportforward.json"
	return &Provider{
		storage:         storage,
		timeNow:         timeNow,
		connPicker:      utils.NewConnectionPicker(),
		portForwardPath: jsonPortForwardPath,
		Fetcher:         updater.New(client),
		client:          client,
		addWireguardKey: addWireguardKey,
		fetchAuthToken:  fetchAuthV3Token,
	}
}

func (p *Provider) Name() string {
	return providers.PrivateInternetAccess
}
