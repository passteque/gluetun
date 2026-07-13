package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/routing"
)

type temporaryConnectionRules struct {
	connection       models.Connection
	interfaces       []string
	cleanupRequested bool
}

// TempAllowConnection temporarily allows one exact destination IP, protocol
// and port through the default-route interfaces matching its address family.
// The returned function removes every rule added by this call.
func (c *Config) TempAllowConnection(ctx context.Context, connection models.Connection) (
	remove func(context.Context) error, err error,
) {
	switch {
	case !connection.IP.IsValid():
		return nil, errors.New("connection IP is not set")
	case connection.Port == 0:
		return nil, errors.New("connection port is not set")
	case connection.Protocol != constants.TCP && connection.Protocol != constants.UDP:
		return nil, fmt.Errorf("connection protocol is not supported: %s", connection.Protocol)
	}

	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	if !c.enabled {
		return func(context.Context) error { return nil }, nil
	}

	cleanupCtx, cancelCleanup := newTemporaryCleanupContext(ctx)
	err = c.sweepTemporaryConnectionRules(cleanupCtx, false)
	cancelCleanup()
	if err != nil {
		return nil, fmt.Errorf("sweeping previous temporary output connections: %w", err)
	}

	interfaces := defaultRouteInterfacesForIP(c.defaultRoutes, connection.IP)
	if len(interfaces) == 0 {
		return nil, errors.New("default route for connection IP address family is not found")
	}

	rules := &temporaryConnectionRules{
		connection: connection,
		interfaces: make([]string, 0, len(interfaces)),
	}
	for _, interfaceName := range interfaces {
		rules.interfaces = append(rules.interfaces, interfaceName)
		if c.temporaryRules == nil {
			c.temporaryRules = make(map[*temporaryConnectionRules]struct{})
		}
		c.temporaryRules[rules] = struct{}{}

		const bootstrapFirewallMark uint32 = 51820
		const remove = false
		err = c.impl.AcceptOutputMarked(ctx, connection.Protocol, interfaceName,
			connection.IP, connection.Port, bootstrapFirewallMark, remove)
		if err != nil {
			rules.cleanupRequested = true
			cleanupCtx, cancelCleanup := newTemporaryCleanupContext(ctx)
			cleanupErr := c.removeTemporaryConnectionRules(cleanupCtx, rules)
			cancelCleanup()
			allowErr := fmt.Errorf("allowing temporary output connection: %w", err)
			return nil, errors.Join(allowErr, cleanupErr)
		}
	}

	return func(removeCtx context.Context) error {
		c.stateMutex.Lock()
		defer c.stateMutex.Unlock()
		_, outstanding := c.temporaryRules[rules]
		if !outstanding {
			return nil
		}

		rules.cleanupRequested = true
		cleanupCtx, cancelCleanup := newTemporaryCleanupContext(removeCtx)
		defer cancelCleanup()
		return c.removeTemporaryConnectionRules(cleanupCtx, rules)
	}, nil
}

func (c *Config) removeTemporaryConnectionRules(ctx context.Context, rules *temporaryConnectionRules) error {
	remainingInterfaces := rules.interfaces[:0]
	errs := make([]error, 0, len(rules.interfaces))
	for _, interfaceName := range rules.interfaces {
		const bootstrapFirewallMark uint32 = 51820
		const remove = true
		err := c.impl.AcceptOutputMarked(ctx, rules.connection.Protocol, interfaceName,
			rules.connection.IP, rules.connection.Port, bootstrapFirewallMark, remove)
		if err != nil {
			remainingInterfaces = append(remainingInterfaces, interfaceName)
			errs = append(errs, err)
		}
	}
	rules.interfaces = remainingInterfaces
	if len(rules.interfaces) == 0 {
		delete(c.temporaryRules, rules)
	}
	if len(errs) > 0 {
		return fmt.Errorf("removing temporary output connection: %w", errors.Join(errs...))
	}
	return nil
}

func (c *Config) sweepTemporaryConnectionRules(ctx context.Context, includeActive bool) error {
	errs := make([]error, 0, len(c.temporaryRules))
	for rules := range c.temporaryRules {
		if !includeActive && !rules.cleanupRequested {
			continue
		}
		rules.cleanupRequested = true
		err := c.removeTemporaryConnectionRules(ctx, rules)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("sweeping temporary output connections: %w", errors.Join(errs...))
	}
	return nil
}

func newTemporaryCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	const cleanupTimeout = 5 * time.Second
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func defaultRouteInterfacesForIP(defaultRoutes []routing.DefaultRoute, ip netip.Addr) []string {
	interfaces := make([]string, 0, len(defaultRoutes))
	seen := make(map[string]struct{}, len(defaultRoutes))
	for _, defaultRoute := range defaultRoutes {
		addressFamilyMatches := ip.Is4() == (defaultRoute.Family == netlink.FamilyV4)
		if !addressFamilyMatches {
			continue
		}
		_, alreadySeen := seen[defaultRoute.NetInterface]
		if alreadySeen {
			continue
		}
		seen[defaultRoute.NetInterface] = struct{}{}
		interfaces = append(interfaces, defaultRoute.NetInterface)
	}
	return interfaces
}
