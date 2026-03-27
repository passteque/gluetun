package vpn

import (
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/loopstate"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/vpn/state"
	"github.com/qdm12/log"
)

type Loop struct {
	statusManager  *loopstate.State
	state          *state.State
	providers      Providers
	storage        Storage
	healthSettings settings.Health
	healthChecker  HealthChecker
	healthServer   HealthServer
	// Fixed parameters
	buildInfo     models.BuildInformation
	versionInfo   bool
	ipv6Supported bool
	vpnInputPorts []uint16 // TODO make changeable through stateful firewall
	// Configurators
	openvpnConf OpenVPN
	netLinker   NetLinker
	fw          Firewall
	routing     Routing
	portForward PortForward
	publicip    PublicIPLoop
	dnsLooper   DNSLoop
	boringPoll  Service
	// Other objects
	cmder  Cmder // for OpenVPN and up/down commands
	logger log.LoggerInterface
	client *http.Client
	// Internal channels and values
	stop        <-chan struct{}
	stopped     chan<- struct{}
	start       <-chan struct{}
	running     chan<- models.LoopStatus
	userTrigger bool
	// Internal constant values
	backoffTime time.Duration
}

const (
	defaultBackoffTime = 15 * time.Second
)

func NewLoop(vpnSettings settings.VPN, ipv6Supported bool, vpnInputPorts []uint16,
	providers Providers, storage Storage, boringPoll Service,
	healthSettings settings.Health, healthChecker HealthChecker, healthServer HealthServer,
	openvpnConf OpenVPN, netLinker NetLinker, fw Firewall, routing Routing,
	portForward PortForward, cmder Cmder,
	publicip PublicIPLoop, dnsLooper DNSLoop,
	logger log.LoggerInterface, client *http.Client,
	buildInfo models.BuildInformation, versionInfo bool,
) *Loop {
	start := make(chan struct{})
	running := make(chan models.LoopStatus)
	stop := make(chan struct{})
	stopped := make(chan struct{})

	statusManager := loopstate.New(constants.Stopped, start, running, stop, stopped)
	state := state.New(statusManager, vpnSettings)

	return &Loop{
		statusManager:  statusManager,
		state:          state,
		providers:      providers,
		storage:        storage,
		healthSettings: healthSettings,
		healthChecker:  healthChecker,
		healthServer:   healthServer,
		buildInfo:      buildInfo,
		versionInfo:    versionInfo,
		ipv6Supported:  ipv6Supported,
		vpnInputPorts:  vpnInputPorts,
		boringPoll:     boringPoll,
		openvpnConf:    openvpnConf,
		netLinker:      netLinker,
		fw:             fw,
		routing:        routing,
		portForward:    portForward,
		publicip:       publicip,
		dnsLooper:      dnsLooper,
		cmder:          cmder,
		logger:         logger,
		client:         client,
		start:          start,
		running:        running,
		stop:           stop,
		stopped:        stopped,
		userTrigger:    true,
		backoffTime:    defaultBackoffTime,
	}
}
