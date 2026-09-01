package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/firewall/nftables"
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
// if no firewall implementation is available.
func NewConfig(ctx context.Context, implementation string,
	logger, iptablesLogger Logger, runner CmdRunner,
	defaultRoutes []routing.DefaultRoute, localNetworks []routing.LocalNetwork,
) (config *Config, err error) {
	var impl firewallImpl
	var customRulesPath string
	// TODO after v3.42 release, use nftables if [nftables.IsSupported] is true.
	switch implementation {
	case "auto", "iptables":
		impl, err = iptables.New(ctx, runner, iptablesLogger)
		if err != nil {
			return nil, fmt.Errorf("creating iptables firewall: %w", err)
		}
		customRulesPath = "/iptables/post-rules.txt"
	case "nftables":
		impl = nftables.New(runner, logger)
		customRulesPath = "/gluetun/firewall/nftables/post-rules.txt"
	default:
		return nil, fmt.Errorf("unknown firewall implementation: %s", implementation)
	}

	return &Config{
		runner:            runner,
		logger:            logger,
		allowedInputPorts: make(map[uint16]map[string]struct{}),
		// Obtained from routing
		defaultRoutes:   defaultRoutes,
		localNetworks:   localNetworks,
		impl:            impl,
		customRulesPath: customRulesPath,
	}, nil
}
