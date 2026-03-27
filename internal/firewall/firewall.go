package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/routing"
)

type Config struct {
	runner        CmdRunner
	logger        Logger
	defaultRoutes []routing.DefaultRoute
	localNetworks []routing.LocalNetwork

	// Fixed
	impl            firewallImpl
	customRulesPath string

	// State
	enabled           bool
	restore           func(context.Context)
	vpnConnection     models.Connection
	vpnIntf           string
	outboundSubnets   []netip.Prefix
	allowedInputPorts map[uint16]map[string]struct{} // port to interfaces set mapping
	portRedirections  portRedirections
	stateMutex        sync.Mutex
}

// NewConfig creates a new Config instance and returns an error
// if no iptables implementation is available.
func NewConfig(ctx context.Context, logger, iptablesLogger Logger,
	runner CmdRunner, defaultRoutes []routing.DefaultRoute,
	localNetworks []routing.LocalNetwork,
) (config *Config, err error) {
	impl, err := iptables.New(ctx, runner, iptablesLogger)
	if err != nil {
		return nil, fmt.Errorf("creating iptables firewall: %w", err)
	}

	return &Config{
		runner:            runner,
		logger:            logger,
		allowedInputPorts: make(map[uint16]map[string]struct{}),
		// Obtained from routing
		defaultRoutes:   defaultRoutes,
		localNetworks:   localNetworks,
		impl:            impl,
		customRulesPath: "/iptables/post-rules.txt",
	}, nil
}
