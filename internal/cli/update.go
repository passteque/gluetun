package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/dns/v2/pkg/doh"
	dnsprovider "github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/openvpn/extract"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/publicip/api"
	"github.com/qdm12/gluetun/internal/storage"
	"github.com/qdm12/gluetun/internal/updater"
	"github.com/qdm12/gluetun/internal/updater/resolver"
	"github.com/qdm12/gluetun/internal/updater/unzip"
)

var (
	ErrModeUnspecified     = errors.New("at least one of -enduser or -maintainer must be specified")
	ErrNoProviderSpecified = errors.New("no provider was specified")
	ErrUsernameMissing     = errors.New("username is required for this provider")
	ErrPasswordMissing     = errors.New("password is required for this provider")
)

type UpdaterLogger interface {
	Info(s string)
	Warn(s string)
	Error(s string)
}

func (c *CLI) Update(ctx context.Context, args []string, logger UpdaterLogger) error {
	options := settings.Updater{}
	var endUserMode, maintainerMode, updateAll bool
	var dnsServer, csvProviders, ipToken, protonUsername, protonEmail, protonPassword string
	flagSet := flag.NewFlagSet("update", flag.ExitOnError)
	flagSet.BoolVar(&endUserMode, "enduser", false, "Write results to /gluetun/servers.json (for end users)")
	flagSet.BoolVar(&maintainerMode, "maintainer", false,
		"Write results to ./internal/storage/servers.json to modify the program (for maintainers)")
	flagSet.StringVar(&dnsServer, "dns", "", "no longer used, your DNS will use DoH with Cloudflare and Google")
	const defaultMinRatio = 0.8
	flagSet.Float64Var(&options.MinRatio, "minratio", defaultMinRatio,
		"Minimum ratio of servers to find for the update to succeed")
	flagSet.BoolVar(&updateAll, "all", false, "Update servers for all VPN providers")
	flagSet.StringVar(&csvProviders, "providers", "", "CSV string of VPN providers to update server data for")
	flagSet.StringVar(&ipToken, "ip-token", "", "IP data service token (e.g. ipinfo.io) to use")
	flagSet.StringVar(&protonUsername, "proton-username", "",
		"(Retro-compatibility) Username to use to authenticate with Proton. Use -proton-email instead.") // v4 remove this
	flagSet.StringVar(&protonEmail, "proton-email", "", "Email to use to authenticate with Proton")
	flagSet.StringVar(&protonPassword, "proton-password", "", "Password to use to authenticate with Proton")
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if dnsServer != "" {
		logger.Warn("The -dns flag is no longer used, your DNS will use DoH with Cloudflare and Google")
	}

	if !endUserMode && !maintainerMode {
		return fmt.Errorf("%w", ErrModeUnspecified)
	}

	if updateAll {
		options.Providers = providers.All()
	} else {
		if csvProviders == "" {
			return fmt.Errorf("%w", ErrNoProviderSpecified)
		}
		options.Providers = strings.Split(csvProviders, ",")
	}

	if slices.Contains(options.Providers, providers.Protonvpn) {
		if protonEmail == "" && protonUsername != "" {
			protonEmail = protonUsername + "@protonmail.com"
			logger.Warn("use -proton-email instead of -proton-username in the future. " +
				"This assumes the email is " + protonEmail + " and may not work.")
		}
		options.ProtonEmail = &protonEmail
		options.ProtonPassword = &protonPassword
	}

	options.SetDefaults(options.Providers[0])

	err := options.Validate()
	if err != nil {
		return fmt.Errorf("options validation failed: %w", err)
	}

	serversDataPath := constants.ServersData
	if maintainerMode {
		serversDataPath = ""
	}
	storage, err := storage.New(logger, serversDataPath)
	if err != nil {
		return fmt.Errorf("creating servers storage: %w", err)
	}

	dohSettings := doh.Settings{
		UpstreamResolvers: []dnsprovider.Provider{
			dnsprovider.Cloudflare(),
			dnsprovider.Google(),
		},
	}
	dnsDialer, err := doh.New(dohSettings)
	if err != nil {
		return fmt.Errorf("creating DoH dialer: %w", err)
	}

	const clientTimeout = 10 * time.Second
	httpClient := &http.Client{Timeout: clientTimeout}
	unzipper := unzip.New(httpClient)
	parallelResolver := resolver.NewParallelResolver(dnsDialer)
	nameTokenPairs := []api.NameToken{
		{Name: string(api.IPInfo), Token: ipToken},
		{Name: string(api.IP2Location)},
		{Name: string(api.IfConfigCo)},
	}
	fetchers, err := api.New(nameTokenPairs, httpClient)
	if err != nil {
		return fmt.Errorf("creating public IP fetchers: %w", err)
	}
	ipFetcher := api.NewResilient(fetchers, logger)

	openvpnFileExtractor := extract.New()

	providers := provider.NewProviders(storage, time.Now, logger, httpClient,
		unzipper, parallelResolver, ipFetcher, openvpnFileExtractor, options)

	updater := updater.New(httpClient, storage, providers, logger)
	err = updater.UpdateServers(ctx, options.Providers, options.MinRatio)
	if err != nil {
		return fmt.Errorf("updating server information: %w", err)
	}

	if maintainerMode {
		err := storage.FlushToFile(c.repoServersPath)
		if err != nil {
			return fmt.Errorf("writing servers data to embedded JSON file: %w", err)
		}
	}

	return nil
}
