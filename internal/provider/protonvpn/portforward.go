package protonvpn

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/natpmp"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

// ErrPortsReassigned is returned when the gateway reassigns external ports
// whilst refreshing a mapping and the port forwarding service has no way to
// apply them. Continuing would leave the client listening on a port that is
// no longer forwarded, so the caller restarts port forwarding instead.
var ErrPortsReassigned = errors.New("gateway reassigned external ports")

// PortForward obtains a VPN server side port forwarded from ProtonVPN gateway.
func (p *Provider) PortForward(ctx context.Context, objects utils.PortForwardObjects) (
	internalToExternalPorts map[uint16]uint16, err error,
) {
	if !objects.CanPortForward {
		return nil, errors.New("server does not support port forwarding")
	} else if objects.PortsCount == 0 {
		return nil, nil //nolint:nilnil
	}

	client := natpmp.New()
	_, externalIPv4Address, err := client.ExternalAddress(ctx, objects.Gateway)
	if err != nil {
		switch {
		case strings.HasSuffix(err.Error(), "connection refused"):
			err = fmt.Errorf("%w - make sure you have +pmp at the end of your OpenVPN username "+
				"or that your Wireguard key is set to work with PMP", err)
		case strings.Contains(err.Error(), "i/o timeout"):
			err = fmt.Errorf("%w - make sure FIREWALL_OUTBOUND_SUBNETS does not conflict with "+
				"the VPN gateway ip address %s", err, objects.Gateway)
		}
		return nil, fmt.Errorf("getting external IPv4 address: %w", err)
	}

	logger := objects.Logger

	logger.Debug("gateway external IPv4 address is " + externalIPv4Address.String())

	p.internalToExternalPorts = make(map[uint16]uint16, objects.PortsCount)
	const lifetime = 60 * time.Second

	// Only one port can be a symmetric mapping
	const internalPort, externalPort = 0, 1
	_, assignedExternalPort, err := addPortMappingTCPUDP(ctx,
		client, logger, objects.Gateway, internalPort, externalPort, lifetime)
	// Note the returned assignedInternalPort is always 0 in this case
	if err != nil {
		return nil, fmt.Errorf("adding first port mapping: %w", err)
	}
	p.internalToExternalPorts[assignedExternalPort] = assignedExternalPort

	// Extra ports must be non-symmetric, meaning that the internal port is
	// different from the external port.
	const nonSymmetricPortStart = uint16(56789)
	nonSymmetricPortStartMinusOne := nonSymmetricPortStart - 1
	if _, ok := p.internalToExternalPorts[nonSymmetricPortStart]; ok {
		nonSymmetricPortStartMinusOne++
	}
	for i := uint16(1); i < objects.PortsCount; i++ {
		internalPort := nonSymmetricPortStartMinusOne + i
		const externalPort = 0
		assignedInternalPort, assignedExternalPort, err := addPortMappingTCPUDP(ctx,
			client, logger, objects.Gateway, internalPort, externalPort, lifetime)
		if err != nil {
			return nil, fmt.Errorf("adding %d/%d port mapping: %w", i+1, objects.PortsCount, err)
		}
		p.internalToExternalPorts[assignedInternalPort] = assignedExternalPort
	}

	return maps.Clone(p.internalToExternalPorts), nil
}

func addPortMappingTCPUDP(ctx context.Context, client *natpmp.Client, logger utils.Logger,
	gateway netip.Addr, internalPort, externalPort uint16, lifetime time.Duration,
) (assignedInternalPort, assignedExternalPort uint16, err error) {
	var assignedLifetime time.Duration
	protocolToExternalPort := map[string]uint16{
		"tcp": 0,
		"udp": 0,
	}
	for _, protocol := range [...]string{"udp", "tcp"} {
		protocolStr := strings.ToUpper(protocol)
		_, assignedInternalPort, assignedExternalPort, assignedLifetime, err = client.AddPortMapping(
			ctx, gateway, protocol, internalPort, externalPort, lifetime)
		if err != nil {
			return 0, 0, fmt.Errorf("adding %s port mapping: %w", protocolStr, err)
		}
		protocolToExternalPort[protocol] = assignedExternalPort
		checkLifetime(logger, protocolStr, lifetime, assignedLifetime)
		// Note the external port is deliberately not validated against the
		// requested one. The gateway is free to hand back a different external
		// port, notably when refreshing an existing mapping, and the caller
		// decides what to do with the port it actually received.
		if internalPort != assignedInternalPort {
			return 0, 0, fmt.Errorf("%s internal port requested as %d but received %d",
				protocolStr, internalPort, assignedInternalPort)
		}
	}

	if protocolToExternalPort["tcp"] != protocolToExternalPort["udp"] {
		return 0, 0, fmt.Errorf("TCP and UDP external ports differ: %d and %d",
			protocolToExternalPort["tcp"], protocolToExternalPort["udp"])
	}

	return assignedInternalPort, assignedExternalPort, nil
}

// portsMapToString describes an external port reassignment as a sorted list of
// "was -> now" pairs, keyed by internal port so the output is deterministic.
func portsMapToString(previous, current map[uint16]uint16) string {
	internalPorts := slices.Sorted(maps.Keys(current))
	pairs := make([]string, 0, len(internalPorts))
	for _, internalPort := range internalPorts {
		was, ok := previous[internalPort]
		if !ok || was == current[internalPort] {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%d -> %d", was, current[internalPort]))
	}
	return strings.Join(pairs, ", ")
}

func checkLifetime(logger utils.Logger, protocol string,
	requested, actual time.Duration,
) {
	if requested != actual {
		logger.Warn(fmt.Sprintf("assigned %s port lifetime %s differs"+
			" from requested lifetime %s", strings.ToUpper(protocol),
			actual, requested))
	}
}

func (p *Provider) KeepPortForward(ctx context.Context,
	objects utils.PortForwardObjects,
) (err error) {
	client := natpmp.New()
	const refreshTimeout = 45 * time.Second
	timer := time.NewTimer(refreshTimeout)
	logger := objects.Logger
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		objects.Logger.Debug("refreshing forwarded ports since 45 seconds have elapsed")
		const lifetime = 60 * time.Second
		refreshedPorts := make(map[uint16]uint16, len(p.internalToExternalPorts))
		portsChanged := false
		for internalPort, externalPort := range p.internalToExternalPorts {
			assignedInternalPort, assignedExternalPort, err := addPortMappingTCPUDP(ctx,
				client, logger, objects.Gateway, internalPort, externalPort, lifetime)
			if err != nil {
				return fmt.Errorf("refreshing port mapping for internal port %d and external port %d: %w",
					internalPort, externalPort, err)
			}
			refreshedPorts[assignedInternalPort] = assignedExternalPort
			if assignedExternalPort != externalPort {
				portsChanged = true
				logger.Info(fmt.Sprintf("gateway reassigned external port %d to %d",
					externalPort, assignedExternalPort))
				continue
			}
			objects.Logger.Debug(fmt.Sprintf("port forwarded %d maintained", externalPort))
		}

		if portsChanged {
			if objects.OnPortsChanged == nil {
				return fmt.Errorf("%w: %s", ErrPortsReassigned,
					portsMapToString(p.internalToExternalPorts, refreshedPorts))
			}
			p.internalToExternalPorts = refreshedPorts
			err = objects.OnPortsChanged(ctx, maps.Clone(refreshedPorts))
			if err != nil {
				return fmt.Errorf("handling reassigned ports: %w", err)
			}
		}

		timer.Reset(refreshTimeout)
	}
}
