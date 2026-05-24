package protonvpn

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/natpmp"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

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
	for i := uint16(1); i < objects.PortsCount; i++ {
		const nonSymmetricPortStart uint16 = 56789 - 1
		internalPort := nonSymmetricPortStart + i
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
	for _, protocol := range [...]string{"udp", "tcp"} {
		protocolStr := strings.ToUpper(protocol)
		_, assignedInternalPort, assignedExternalPort, assignedLifetime, err = client.AddPortMapping(
			ctx, gateway, protocol, internalPort, externalPort, lifetime)
		if err != nil {
			return 0, 0, fmt.Errorf("adding %s port mapping: %w", protocolStr, err)
		}
		checkLifetime(logger, protocolStr, lifetime, assignedLifetime)
		if internalPort != assignedInternalPort {
			return 0, 0, fmt.Errorf("%s internal port requested as %d but received %d",
				protocolStr, internalPort, assignedInternalPort)
		} else if externalPort != 0 && externalPort != 1 && externalPort != assignedExternalPort {
			return 0, 0, fmt.Errorf("%s external port requested as %d but received %d",
				protocolStr, externalPort, assignedExternalPort)
		}
	}
	return assignedInternalPort, assignedExternalPort, nil
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
		for internalPort, externalPort := range p.internalToExternalPorts {
			_, _, err := addPortMappingTCPUDP(ctx, client, logger, objects.Gateway, internalPort, externalPort, lifetime)
			if err != nil {
				return fmt.Errorf("refreshing port mapping for internal port %d and external port %d: %w",
					internalPort, externalPort, err)
			}
			objects.Logger.Debug(fmt.Sprintf("port forwarded %d maintained", externalPort))
		}

		timer.Reset(refreshTimeout)
	}
}
