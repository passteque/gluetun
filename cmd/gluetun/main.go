package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	_ "github.com/breml/rootcerts"
	"github.com/qdm12/dns/v2/pkg/doh"
	dnsprovider "github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/alpine"
	"github.com/qdm12/gluetun/internal/boringpoll"
	"github.com/qdm12/gluetun/internal/cli"
	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/configuration/sources/files"
	"github.com/qdm12/gluetun/internal/configuration/sources/secrets"
	"github.com/qdm12/gluetun/internal/constants"
	copenvpn "github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/dns"
	"github.com/qdm12/gluetun/internal/firewall"
	"github.com/qdm12/gluetun/internal/healthcheck"
	"github.com/qdm12/gluetun/internal/httpproxy"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/openvpn"
	"github.com/qdm12/gluetun/internal/openvpn/extract"
	"github.com/qdm12/gluetun/internal/portforward"
	"github.com/qdm12/gluetun/internal/pprof"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/publicip"
	"github.com/qdm12/gluetun/internal/routing"
	"github.com/qdm12/gluetun/internal/server"
	"github.com/qdm12/gluetun/internal/shadowsocks"
	"github.com/qdm12/gluetun/internal/storage"
	"github.com/qdm12/gluetun/internal/tun"
	updater "github.com/qdm12/gluetun/internal/updater/loop"
	"github.com/qdm12/gluetun/internal/updater/resolver"
	"github.com/qdm12/gluetun/internal/updater/unzip"
	"github.com/qdm12/gluetun/internal/vpn"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/qdm12/goshutdown"
	"github.com/qdm12/goshutdown/goroutine"
	"github.com/qdm12/goshutdown/group"
	"github.com/qdm12/goshutdown/order"
	"github.com/qdm12/gosplash"
	"github.com/qdm12/log"
)

//nolint:gochecknoglobals
var (
	version = "unknown"
	commit  = "unknown"
	created = "an unknown date"
)

func main() {
	buildInfo := models.BuildInformation{
		Version: version,
		Commit:  commit,
		Created: created,
	}

	background := context.Background()
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(background)

	logger := log.New(log.SetLevel(log.LevelInfo))

	args := os.Args
	tun := tun.New()
	netLinkDebugLogger := logger.New(log.SetComponent("netlink"))
	netLinker := netlink.New(netLinkDebugLogger)
	cli := cli.New()
	cmder := command.New()

	reader := reader.New(reader.Settings{
		Sources: []reader.Source{
			secrets.New(logger),
			files.New(logger),
			env.New(env.Settings{}),
		},
		HandleDeprecatedKey: func(source, deprecatedKey, currentKey string) {
			logger.Warn("You are using the old " + source + " " + deprecatedKey +
				", please consider changing it to " + currentKey)
		},
	})

	errorCh := make(chan error)
	go func() {
		errorCh <- _main(ctx, buildInfo, args, logger, reader, tun, netLinker, cmder, cli)
	}()

	// Wait for OS signal or run error
	var err error
	select {
	case receivedSignal := <-signalCh:
		signal.Stop(signalCh)
		fmt.Println("")
		logger.Warn("Caught OS signal " + receivedSignal.String() + ", shutting down")
		cancel()
	case err = <-errorCh:
		close(errorCh)
		if err == nil { // expected exit such as healthcheck
			os.Exit(0)
		}
		logger.Error(err.Error())
		cancel()
	}

	// Shutdown timed sequence, and force exit on second OS signal
	const shutdownGracePeriod = 5 * time.Second
	timer := time.NewTimer(shutdownGracePeriod)
	select {
	case shutdownErr := <-errorCh:
		timer.Stop()
		if shutdownErr != nil {
			logger.Warnf("Shutdown failed: %s", shutdownErr)
			os.Exit(1)
		}

		logger.Info("Shutdown successful")
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case <-timer.C:
		logger.Warn("Shutdown timed out")
		os.Exit(1)
	}
}

var errCommandUnknown = errors.New("command is unknown")

//nolint:gocognit,gocyclo,maintidx
func _main(ctx context.Context, buildInfo models.BuildInformation,
	args []string, logger log.LoggerInterface, reader *reader.Reader,
	tun Tun, netLinker netLinker, cmder RunStarter,
	cli clier,
) error {
	if len(args) > 1 { // cli operation
		switch args[1] {
		case "healthcheck":
			return cli.HealthCheck(ctx, reader, logger)
		case "clientkey":
			return cli.ClientKey(args[2:])
		case "openvpnconfig":
			return cli.OpenvpnConfig(logger, reader, netLinker)
		case "update":
			return cli.Update(ctx, args[2:], logger)
		case "format-servers":
			return cli.FormatServers(args[2:])
		case "genkey":
			return cli.GenKey(args[2:])
		default:
			return fmt.Errorf("%w: %s", errCommandUnknown, args[1])
		}
	}

	defer fmt.Println(gluetunLogo)

	announcementExp, err := time.Parse(time.RFC3339, "2026-04-30T00:00:00Z")
	if err != nil {
		return err
	}
	splashSettings := gosplash.Settings{
		User:         "qdm12",
		Repository:   "gluetun",
		Emails:       []string{"quentin.mcgaw@gmail.com"},
		Version:      buildInfo.Version,
		Commit:       buildInfo.Commit,
		Created:      buildInfo.Created,
		Announcement: "Set BORINGPOLL_GLUETUNCOM=on to help combat AI slop and shutdown that scam website",
		AnnounceExp:  announcementExp,
		// Sponsor information
		PaypalUser:    "qmcgaw",
		GithubSponsor: "qdm12",
	}
	for _, line := range gosplash.MakeLines(splashSettings) {
		fmt.Println(line)
	}

	var allSettings settings.Settings
	err = allSettings.Read(reader, logger)
	if err != nil {
		return err
	}
	allSettings.SetDefaults()

	// Note: no need to validate minimal settings for the firewall:
	// - global log level is parsed below
	// - firewall Debug and Enabled are booleans parsed from source
	logLevel, err := log.ParseLevel(allSettings.Log.Level)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	logger.Patch(log.SetLevel(logLevel))
	netLinker.PatchLoggerLevel(logLevel)

	routingLogger := logger.New(log.SetComponent("routing"))
	if *allSettings.Firewall.Debug { // To remove in v4
		routingLogger.Patch(log.SetLevel(log.LevelDebug))
	}
	routingConf := routing.New(netLinker, routingLogger)

	defaultRoutes, err := routingConf.DefaultRoutes()
	if err != nil {
		return err
	}

	localNetworks, err := routingConf.LocalNetworks()
	if err != nil {
		return err
	}

	firewallLogger := logger.New(log.SetComponent("firewall"))
	if *allSettings.Firewall.Debug { // To remove in v4
		firewallLogger.Patch(log.SetLevel(log.LevelDebug))
	}
	firewallConf, err := firewall.NewConfig(ctx, firewallLogger, cmder,
		defaultRoutes, localNetworks)
	if err != nil {
		return err
	}

	if *allSettings.Firewall.Enabled {
		err = firewallConf.SetEnabled(ctx, true)
		if err != nil {
			return err
		}
		err = netLinker.FlushConntrack()
		if err != nil {
			logger.Warnf("flushing conntrack failed: %s", err)
		}
	}

	// TODO run this in a loop or in openvpn to reload from file without restarting
	storageLogger := logger.New(log.SetComponent("storage"))
	storage, err := storage.New(storageLogger, *allSettings.Storage.Filepath)
	if err != nil {
		return err
	}

	ipv6Supported, err := netLinker.IsIPv6Supported()
	if err != nil {
		return fmt.Errorf("checking for IPv6 support: %w", err)
	}

	err = allSettings.Validate(storage, ipv6Supported, logger)
	if err != nil {
		return err
	}

	allSettings.Pprof.HTTPServer.Logger = logger.New(log.SetComponent("pprof"))
	pprofServer, err := pprof.New(allSettings.Pprof)
	if err != nil {
		return fmt.Errorf("creating Pprof server: %w", err)
	}

	puid, pgid := int(*allSettings.System.PUID), int(*allSettings.System.PGID)

	const clientTimeout = 35 * time.Second
	httpClient := &http.Client{Timeout: clientTimeout}
	// Create configurators
	alpineConf := alpine.New()
	ovpnConf := openvpn.New(
		logger.New(log.SetComponent("openvpn configurator")),
		cmder, puid, pgid)
	ovpnVersion := ovpnConf.Version26
	if allSettings.VPN.OpenVPN.Version == copenvpn.Openvpn25 {
		ovpnVersion = ovpnConf.Version25
	}

	err = printVersions(ctx, logger, []printVersionElement{
		{name: "Alpine", getVersion: alpineConf.Version},
		{name: "OpenVPN", getVersion: ovpnVersion},
		{name: "Firewall", getVersion: firewallConf.Version},
	})
	if err != nil {
		return err
	}

	logger.Info(allSettings.String())

	for _, warning := range allSettings.Warnings() {
		logger.Warn(warning)
	}

	const permission = fs.FileMode(0o644)
	err = os.MkdirAll("/tmp/gluetun", permission)
	if err != nil {
		return err
	}
	err = os.MkdirAll("/gluetun", permission)
	if err != nil {
		return err
	}

	const defaultUsername = "nonrootuser"
	nonRootUsername, err := alpineConf.CreateUser(defaultUsername, puid)
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}
	if nonRootUsername != defaultUsername {
		logger.Info("using existing username " + nonRootUsername + " corresponding to user id " + fmt.Sprint(puid))
	}
	allSettings.VPN.OpenVPN.ProcessUser = nonRootUsername

	if err := routingConf.Setup(); err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			logger.Warn("💡 Tip: Are you passing NET_ADMIN capability to gluetun?")
		}
		return fmt.Errorf("setting up routing: %w", err)
	}
	defer func() {
		routingLogger.Info("routing cleanup...")
		if err := routingConf.TearDown(); err != nil {
			routingLogger.Error("cannot teardown routing: " + err.Error())
		}
	}()

	if err := firewallConf.SetOutboundSubnets(ctx, allSettings.Firewall.OutboundSubnets); err != nil {
		return err
	}
	if err := routingConf.SetOutboundRoutes(allSettings.Firewall.OutboundSubnets); err != nil {
		return err
	}

	err = routingConf.AddLocalRules(localNetworks)
	if err != nil {
		return fmt.Errorf("adding local rules: %w", err)
	}

	const tunDevice = "/dev/net/tun"
	err = tun.Check(tunDevice)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking TUN device: %w (see the Wiki errors/tun page)", err)
		}
		logger.Info(err.Error() + "; creating it...")
		err = tun.Create(tunDevice)
		if err != nil {
			return fmt.Errorf("creating tun device: %w", err)
		}
	}

	for _, port := range allSettings.Firewall.InputPorts {
		for _, defaultRoute := range defaultRoutes {
			err = firewallConf.SetAllowedPort(ctx, port, defaultRoute.NetInterface)
			if err != nil {
				return err
			}
		}
	} // TODO move inside firewall?

	// Shutdown settings
	const totalShutdownTimeout = 3 * time.Second
	const defaultShutdownTimeout = 400 * time.Millisecond
	defaultShutdownOnSuccess := func(goRoutineName string) {
		logger.Info(goRoutineName + ": terminated ✔️")
	}
	defaultShutdownOnFailure := func(goRoutineName string, err error) {
		logger.Warn(goRoutineName + ": " + err.Error() + " ⚠️")
	}
	defaultGroupOptions := []group.Option{
		group.OptionTimeout(defaultShutdownTimeout),
		group.OptionOnSuccess(defaultShutdownOnSuccess),
	}

	controlGroupHandler := goshutdown.NewGroupHandler("control", defaultGroupOptions...)
	tickersGroupHandler := goshutdown.NewGroupHandler("tickers", defaultGroupOptions...)
	otherGroupHandler := goshutdown.NewGroupHandler("other", defaultGroupOptions...)

	if *allSettings.Pprof.Enabled {
		// TODO run in run loop so this can be patched at runtime
		pprofReady := make(chan struct{})
		pprofHandler, pprofCtx, pprofDone := goshutdown.NewGoRoutineHandler("pprof server")
		go pprofServer.Run(pprofCtx, pprofReady, pprofDone)
		otherGroupHandler.Add(pprofHandler)
		<-pprofReady
	}

	portForwardLogger := logger.New(log.SetComponent("port forwarding"))
	portForwardLooper := portforward.NewLoop(allSettings.VPN.Provider.PortForwarding,
		routingConf, httpClient, firewallConf, portForwardLogger, cmder, puid, pgid)
	portForwardRunError, err := portForwardLooper.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting port forwarding loop: %w", err)
	}

	dnsLogger := logger.New(log.SetComponent("dns"))
	dnsLooper, err := dns.NewLoop(allSettings.DNS, httpClient,
		dnsLogger, localNetworksToPrefixes(localNetworks))
	if err != nil {
		return fmt.Errorf("creating DNS loop: %w", err)
	}

	dnsHandler, dnsCtx, dnsDone := goshutdown.NewGoRoutineHandler(
		"dns", goroutine.OptionTimeout(defaultShutdownTimeout))
	// wait for dnsLooper.Restart or its ticker launched with RunRestartTicker
	go dnsLooper.Run(dnsCtx, dnsDone)
	otherGroupHandler.Add(dnsHandler)

	dnsTickerHandler, dnsTickerCtx, dnsTickerDone := goshutdown.NewGoRoutineHandler(
		"dns ticker", goroutine.OptionTimeout(defaultShutdownTimeout))
	go dnsLooper.RunRestartTicker(dnsTickerCtx, dnsTickerDone)
	controlGroupHandler.Add(dnsTickerHandler)

	publicIPLooper, err := publicip.NewLoop(allSettings.PublicIP, puid, pgid, httpClient,
		logger.New(log.SetComponent("ip getter")))
	if err != nil {
		return fmt.Errorf("creating public ip loop: %w", err)
	}
	publicIPRunError, err := publicIPLooper.Start(ctx)
	if err != nil {
		return fmt.Errorf("starting public ip loop: %w", err)
	}

	healthLogger := logger.New(log.SetComponent("healthcheck"))
	healthcheckServer := healthcheck.NewServer(allSettings.Health, healthLogger)
	healthServerHandler, healthServerCtx, healthServerDone := goshutdown.NewGoRoutineHandler(
		"HTTP health server", goroutine.OptionTimeout(defaultShutdownTimeout))
	go healthcheckServer.Run(healthServerCtx, healthServerDone)
	healthChecker := healthcheck.NewChecker(healthLogger)

	// Note: we use a separate DoH dialer for the VPN servers data updater, separate from the
	// main DNS local server to make sure no request is blocked by filters.
	dohDialer, err := doh.New(doh.Settings{
		UpstreamResolvers: []dnsprovider.Provider{dnsprovider.Cloudflare(), dnsprovider.Google()},
	})
	if err != nil {
		return fmt.Errorf("creating updater DoH dialer: %w", err)
	}
	updaterLogger := logger.New(log.SetComponent("updater"))

	unzipper := unzip.New(httpClient)
	parallelResolver := resolver.NewParallelResolver(dohDialer)
	openvpnFileExtractor := extract.New()
	providers := provider.NewProviders(storage, time.Now, updaterLogger,
		httpClient, unzipper, parallelResolver, publicIPLooper.Fetcher(),
		openvpnFileExtractor, allSettings.Updater)

	boringPollLogger := logger.New(log.SetComponent("boring poll"))
	boringPoll := boringpoll.New(httpClient, boringPollLogger, allSettings.BoringPoll)

	vpnLogger := logger.New(log.SetComponent("vpn"))
	vpnLooper := vpn.NewLoop(allSettings.VPN, ipv6Supported, allSettings.Firewall.VPNInputPorts,
		providers, storage, boringPoll, allSettings.Health, healthChecker, healthcheckServer,
		ovpnConf, netLinker, firewallConf, routingConf, portForwardLooper, cmder, publicIPLooper,
		dnsLooper, vpnLogger, httpClient, buildInfo, *allSettings.Version.Enabled)
	vpnHandler, vpnCtx, vpnDone := goshutdown.NewGoRoutineHandler(
		"vpn", goroutine.OptionTimeout(time.Second))
	go vpnLooper.Run(vpnCtx, vpnDone)

	updaterLooper := updater.NewLoop(allSettings.Updater,
		providers, storage, httpClient, updaterLogger)
	updaterHandler, updaterCtx, updaterDone := goshutdown.NewGoRoutineHandler(
		"updater", goroutine.OptionTimeout(defaultShutdownTimeout))
	// wait for updaterLooper.Restart() or its ticket launched with RunRestartTicker
	go updaterLooper.Run(updaterCtx, updaterDone)
	tickersGroupHandler.Add(updaterHandler)

	updaterTickerHandler, updaterTickerCtx, updaterTickerDone := goshutdown.NewGoRoutineHandler(
		"updater ticker", goroutine.OptionTimeout(defaultShutdownTimeout))
	go updaterLooper.RunRestartTicker(updaterTickerCtx, updaterTickerDone)
	controlGroupHandler.Add(updaterTickerHandler)

	httpProxyLooper := httpproxy.NewLoop(
		logger.New(log.SetComponent("http proxy")),
		allSettings.HTTPProxy)
	httpProxyHandler, httpProxyCtx, httpProxyDone := goshutdown.NewGoRoutineHandler(
		"http proxy", goroutine.OptionTimeout(defaultShutdownTimeout))
	go httpProxyLooper.Run(httpProxyCtx, httpProxyDone)
	otherGroupHandler.Add(httpProxyHandler)

	shadowsocksLooper := shadowsocks.NewLoop(allSettings.Shadowsocks,
		logger.New(log.SetComponent("shadowsocks")))
	shadowsocksHandler, shadowsocksCtx, shadowsocksDone := goshutdown.NewGoRoutineHandler(
		"shadowsocks proxy", goroutine.OptionTimeout(defaultShutdownTimeout))
	go shadowsocksLooper.Run(shadowsocksCtx, shadowsocksDone)
	otherGroupHandler.Add(shadowsocksHandler)

	httpServerHandler, httpServerCtx, httpServerDone := goshutdown.NewGoRoutineHandler(
		"http server", goroutine.OptionTimeout(defaultShutdownTimeout))
	httpServer, err := server.New(httpServerCtx, allSettings.ControlServer,
		logger.New(log.SetComponent("http server")),
		buildInfo, vpnLooper, portForwardLooper, dnsLooper, updaterLooper, publicIPLooper,
		storage, ipv6Supported)
	if err != nil {
		return fmt.Errorf("setting up control server: %w", err)
	}
	httpServerReady := make(chan struct{})
	go httpServer.Run(httpServerCtx, httpServerReady, httpServerDone)
	<-httpServerReady
	controlGroupHandler.Add(httpServerHandler)

	orderHandler := goshutdown.NewOrderHandler("gluetun",
		order.OptionTimeout(totalShutdownTimeout),
		order.OptionOnSuccess(defaultShutdownOnSuccess),
		order.OptionOnFailure(defaultShutdownOnFailure))
	orderHandler.Append(controlGroupHandler, tickersGroupHandler, healthServerHandler,
		vpnHandler, otherGroupHandler)

	// Start VPN for the first time in a blocking call
	// until the VPN is launched
	_, _ = vpnLooper.ApplyStatus(ctx, constants.Running) // TODO option to disable with variable

	select {
	case <-ctx.Done():
		stoppers := []interface {
			String() string
			Stop() error
		}{
			portForwardLooper, publicIPLooper,
		}
		for _, stopper := range stoppers {
			err := stopper.Stop()
			if err != nil {
				logger.Error(fmt.Sprintf("stopping %s: %s", stopper, err))
			}
		}
	case err := <-portForwardRunError:
		logger.Errorf("port forwarding loop crashed: %s", err)
	case err := <-publicIPRunError:
		logger.Errorf("public IP loop crashed: %s", err)
	}

	return orderHandler.Shutdown(context.Background())
}

type printVersionElement struct {
	name       string
	getVersion func(ctx context.Context) (version string, err error)
}

type infoer interface {
	Info(s string)
}

func printVersions(ctx context.Context, logger infoer,
	elements []printVersionElement,
) (err error) {
	const timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, element := range elements {
		version, err := element.getVersion(ctx)
		if err != nil {
			return fmt.Errorf("getting %s version: %w", element.name, err)
		}
		logger.Info(element.name + " version: " + version)
	}

	return nil
}

func localNetworksToPrefixes(localNetworks []routing.LocalNetwork) (prefixes []netip.Prefix) {
	prefixes = make([]netip.Prefix, len(localNetworks))
	for i, localNetwork := range localNetworks {
		prefixes[i] = localNetwork.IPNet
	}
	return prefixes
}

type netLinker interface {
	Addresser
	Router
	Ruler
	Linker
	IsWireguardSupported() (ok bool, err error)
	IsIPv6Supported() (ok bool, err error)
	FlushConntrack() error
	PatchLoggerLevel(level log.Level)
}

type Addresser interface {
	AddrList(linkIndex uint32, family uint8) (
		addresses []netip.Prefix, err error)
	AddrReplace(linkIndex uint32, addr netip.Prefix) error
}

type Router interface {
	RouteList(family uint8) (routes []netlink.Route, err error)
	RouteAdd(route netlink.Route) error
	RouteDel(route netlink.Route) error
	RouteReplace(route netlink.Route) error
}

type Ruler interface {
	RuleList(family uint8) (rules []netlink.Rule, err error)
	RuleAdd(rule netlink.Rule) error
	RuleDel(rule netlink.Rule) error
}

type Linker interface {
	LinkList() (links []netlink.Link, err error)
	LinkByName(name string) (link netlink.Link, err error)
	LinkByIndex(index uint32) (link netlink.Link, err error)
	LinkAdd(link netlink.Link) (linkIndex uint32, err error)
	LinkDel(linkIndex uint32) (err error)
	LinkSetUp(linkIndex uint32) (err error)
	LinkSetDown(linkIndex uint32) (err error)
	LinkSetMTU(linkIndex, mtu uint32) error
}

type clier interface {
	ClientKey(args []string) error
	FormatServers(args []string) error
	OpenvpnConfig(logger cli.OpenvpnConfigLogger, reader *reader.Reader, ipv6Checker cli.IPv6Checker) error
	HealthCheck(ctx context.Context, reader *reader.Reader, warner cli.Warner) error
	Update(ctx context.Context, args []string, logger cli.UpdaterLogger) error
	GenKey(args []string) error
}

type Tun interface {
	Check(tunDevice string) error
	Create(tunDevice string) error
}

type RunStarter interface {
	Run(cmd *exec.Cmd) (output string, err error)
	Start(cmd *exec.Cmd) (stdoutLines, stderrLines <-chan string,
		waitError <-chan error, err error)
}

const gluetunLogo = `                         @@@
                         @@@@
                        @@@@@@
                       @@@@.@@                       @@@@@@@@@@
                       @@@@.@@@                   @@@@@@@@==@@@@
                      @@@.@..@@                @@@@@@@=@..==@@@@
            @@@@      @@@.@@.@@              @@@@@@===@@@@.=@@@
           @...-@@   @@@@.@@.@@@  @@@     @@@@@@=======@@@=@@@@
           @@@@@@@@  @@@.-%@.+@@@@@@@@  @@@@@%============@@@@
                     @@@.--@..@@@@.-@@@@@@@==============@@@@
              @@@@  @@@-@--@@.@@.---@@@@@==============#@@@@@
              @@@   @@@.@@-@@.@@--@@@@@===============@@@@@@
                   @@@@.@--@@@@@@@@@@================@@@@@@@
                   @@@..--@@*@@@@@@================@@@@+*@@
                   @@@.---@@.@@@@=================@@@@--@@
                  @@@-.---@@@@@@================@@@@*--@@@
                  @@@.:-#@@@@@@===============*@@@@.---@@
                  @@@.-------.@@@============@@@@@@.--@@@
                 @@@..--------:@@@=========@@@@@@@@.--@@@
                 @@@.-@@@@@@@@@@@========@@@@@  @@@.--@@
                 @@.@@@@===============@@@@@ @@@@@@---@@@@@@
                @@@@@@@==============@@@@@@@@@@@@*@---@@@@@@@@
                @@@@@@=============@@@@@ @@@...------------.*@@@
                @@@@%===========@@@@@@ @@@..------@@@@.-----.-@@@
                @@@@@@.=======@@@@@@  @@@.-------@@@@@@-.------=@@
               @@@@@@@@@===@@@@@@     @@.------@@@@   @@@@.-----@@@
               @@@==@@@=@@@@@@@      @@@.-@@@@@@@       @@@@@@@--@@
               @@@@@@@@@@@@@         @@@@@@@@                @@@@@@@
                @@@@@@@@             @@@@                       @@@@
                                                                       `
