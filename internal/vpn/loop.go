package vpn

import (
	"net/http"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/loopstate"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
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
	buildInfo        models.BuildInformation
	versionInfo      bool
	ipv6SupportLevel netlink.IPv6SupportLevel
	vpnInputPorts    []uint16 // TODO make changeable through stateful firewall
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
	healthDone  <-chan struct{}
	// Backoff configuration and state
	backoffMu          sync.Mutex
	backoffTime        time.Duration
	initialBackoffTime time.Duration
	maxBackoffTime     time.Duration
}

const (
	defaultBackoffTime    = 15 * time.Second
	defaultMaxBackoffTime = 5 * time.Minute
)

func NewLoop(vpnSettings settings.VPN, ipv6SupportLevel netlink.IPv6SupportLevel, vpnInputPorts []uint16,
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

	// Initialize healthDone channel to a closed channel so that the first time
	// we call <-l.healthDone it does not block
	healthDone := make(chan struct{})
	close(healthDone)

	initialBackoffTime := defaultBackoffTime
	if healthSettings.RestartDelayInitial != nil {
		initialBackoffTime = *healthSettings.RestartDelayInitial
	}
	maxBackoffTime := defaultMaxBackoffTime
	if healthSettings.RestartDelayMax != nil {
		maxBackoffTime = *healthSettings.RestartDelayMax
	}

	return &Loop{
		statusManager:      statusManager,
		state:              state,
		providers:          providers,
		storage:            storage,
		healthSettings:     healthSettings,
		healthChecker:      healthChecker,
		healthServer:       healthServer,
		buildInfo:          buildInfo,
		versionInfo:        versionInfo,
		ipv6SupportLevel:   ipv6SupportLevel,
		vpnInputPorts:      vpnInputPorts,
		boringPoll:         boringPoll,
		openvpnConf:        openvpnConf,
		netLinker:          netLinker,
		fw:                 fw,
		routing:            routing,
		portForward:        portForward,
		publicip:           publicip,
		dnsLooper:          dnsLooper,
		cmder:              cmder,
		logger:             logger,
		client:             client,
		start:              start,
		running:            running,
		stop:               stop,
		stopped:            stopped,
		userTrigger:        true,
		healthDone:         healthDone,
		backoffTime:        initialBackoffTime,
		initialBackoffTime: initialBackoffTime,
		maxBackoffTime:     maxBackoffTime,
	}
}

func (l *Loop) resetBackoff() {
	l.backoffMu.Lock()
	defer l.backoffMu.Unlock()
	l.backoffTime = l.initialBackoffTime
}

func (l *Loop) getAndAdvanceBackoff() (backoff time.Duration) {
	l.backoffMu.Lock()
	defer l.backoffMu.Unlock()
	backoff = l.backoffTime
	nextBackoff := l.backoffTime * 2
	if nextBackoff > l.maxBackoffTime {
		nextBackoff = l.maxBackoffTime
	}
	l.backoffTime = nextBackoff
	return backoff
}
