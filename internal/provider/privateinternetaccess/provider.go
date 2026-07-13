package privateinternetaccess

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage          common.Storage
	connPicker       *utils.ConnectionPicker
	timeNow          func() time.Time
	newDialingClient func(string, netip.Addr,
		func(context.Context, string, string) (net.Conn, error)) (*http.Client, error)
	common.Fetcher
	// Port forwarding
	portForwardPath string
	apiIP           netip.Addr
}

func New(storage common.Storage, timeNow func() time.Time,
	client *http.Client,
) *Provider {
	const jsonPortForwardPath = "/gluetun/piaportforward.json"
	serverUpdater := updater.New(client)
	return &Provider{
		storage:          storage,
		timeNow:          timeNow,
		connPicker:       utils.NewConnectionPicker(),
		newDialingClient: newHTTPClientDialing,
		portForwardPath:  jsonPortForwardPath,
		Fetcher:          serverUpdater,
	}
}

func (p *Provider) Name() string {
	return providers.PrivateInternetAccess
}
