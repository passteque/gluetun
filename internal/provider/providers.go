package provider

import (
	"fmt"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/airvpn"
	"github.com/qdm12/gluetun/internal/provider/azirevpn"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/custom"
	"github.com/qdm12/gluetun/internal/provider/cyberghost"
	"github.com/qdm12/gluetun/internal/provider/expressvpn"
	"github.com/qdm12/gluetun/internal/provider/fastestvpn"
	"github.com/qdm12/gluetun/internal/provider/giganews"
	"github.com/qdm12/gluetun/internal/provider/hidemyass"
	"github.com/qdm12/gluetun/internal/provider/ipvanish"
	"github.com/qdm12/gluetun/internal/provider/ivpn"
	"github.com/qdm12/gluetun/internal/provider/mullvad"
	"github.com/qdm12/gluetun/internal/provider/nordvpn"
	"github.com/qdm12/gluetun/internal/provider/perfectprivacy"
	"github.com/qdm12/gluetun/internal/provider/privado"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess"
	"github.com/qdm12/gluetun/internal/provider/privatevpn"
	"github.com/qdm12/gluetun/internal/provider/protonvpn"
	"github.com/qdm12/gluetun/internal/provider/purevpn"
	"github.com/qdm12/gluetun/internal/provider/slickvpn"
	"github.com/qdm12/gluetun/internal/provider/surfshark"
	"github.com/qdm12/gluetun/internal/provider/torguard"
	"github.com/qdm12/gluetun/internal/provider/vpnsecure"
	"github.com/qdm12/gluetun/internal/provider/vpnunlimited"
	"github.com/qdm12/gluetun/internal/provider/vyprvpn"
	"github.com/qdm12/gluetun/internal/provider/windscribe"
)

type Providers struct {
	providerNameToProvider map[string]Provider
}

type Storage interface {
	FilterServers(provider string, selection settings.ServerSelection) (
		servers []models.Server, err error)
}

type Extractor interface {
	Data(filepath string) (lines []string,
		connection models.Connection, err error)
}

func NewProviders(storage Storage, timeNow func() time.Time,
	updaterWarner common.Warner, client *http.Client, unzipper common.Unzipper,
	parallelResolver common.ParallelResolver, ipFetcher common.IPFetcher,
	extractor custom.Extractor, credentials settings.Updater,
) *Providers {
	//nolint:lll
	providerNameToProvider := map[string]Provider{
		providers.Airvpn:                airvpn.New(storage, client),
		providers.Azirevpn:              azirevpn.New(storage, client, updaterWarner, credentials.AzirevpnToken),
		providers.Custom:                custom.New(extractor),
		providers.Cyberghost:            cyberghost.New(storage, updaterWarner, parallelResolver),
		providers.Expressvpn:            expressvpn.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.Fastestvpn:            fastestvpn.New(storage, client, updaterWarner, parallelResolver),
		providers.Giganews:              giganews.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.HideMyAss:             hidemyass.New(storage, client, updaterWarner, parallelResolver),
		providers.Ipvanish:              ipvanish.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.Ivpn:                  ivpn.New(storage, client, updaterWarner, parallelResolver),
		providers.Mullvad:               mullvad.New(storage, client),
		providers.Nordvpn:               nordvpn.New(storage, client, updaterWarner),
		providers.Perfectprivacy:        perfectprivacy.New(storage, unzipper, updaterWarner),
		providers.Privado:               privado.New(storage, client, updaterWarner),
		providers.PrivateInternetAccess: privateinternetaccess.New(storage, timeNow, client),
		providers.Privatevpn:            privatevpn.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.Protonvpn:             protonvpn.New(storage, client, updaterWarner, *credentials.ProtonEmail, *credentials.ProtonPassword),
		providers.Purevpn:               purevpn.New(storage, ipFetcher, unzipper, updaterWarner, parallelResolver),
		providers.SlickVPN:              slickvpn.New(storage, client, updaterWarner, parallelResolver),
		providers.Surfshark:             surfshark.New(storage, client, unzipper, updaterWarner, parallelResolver),
		providers.Torguard:              torguard.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.VPNSecure:             vpnsecure.New(storage, client, updaterWarner, parallelResolver),
		providers.VPNUnlimited:          vpnunlimited.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.Vyprvpn:               vyprvpn.New(storage, unzipper, updaterWarner, parallelResolver),
		providers.Windscribe:            windscribe.New(storage, client, updaterWarner),
	}

	targetLength := len(providers.AllWithCustom())
	if len(providerNameToProvider) != targetLength {
		// Programming sanity check
		panic(fmt.Sprintf("invalid number of providers, expected %d but got %d",
			targetLength, len(providerNameToProvider)))
	}

	return &Providers{
		providerNameToProvider: providerNameToProvider,
	}
}

func (p *Providers) Get(providerName string) (provider Provider) { //nolint:ireturn
	provider, ok := p.providerNameToProvider[providerName]
	if !ok {
		panic(fmt.Sprintf("provider %q not found", providerName))
	}
	return provider
}
