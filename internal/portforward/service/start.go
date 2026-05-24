package service

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (s *Service) Start(ctx context.Context) (runError <-chan error, err error) {
	s.startStopMutex.Lock()
	defer s.startStopMutex.Unlock()

	if !*s.settings.Enabled {
		return nil, nil //nolint:nilnil
	}

	s.logger.Info("starting")

	gateway, err := s.routing.VPNLocalGatewayIP(s.settings.Interface)
	if err != nil {
		return nil, fmt.Errorf("getting VPN local gateway IP: %w", err)
	}

	family := netlink.FamilyV4
	if gateway.Is6() {
		family = netlink.FamilyV6
	}
	internalIP, err := s.routing.AssignedIP(s.settings.Interface, family)
	if err != nil {
		return nil, fmt.Errorf("getting VPN assigned IP address: %w", err)
	}

	obj := utils.PortForwardObjects{
		Logger:         s.logger,
		Gateway:        gateway,
		InternalIP:     internalIP,
		Client:         s.client,
		ServerName:     s.settings.ServerName,
		CanPortForward: s.settings.CanPortForward,
		Username:       s.settings.Username,
		Password:       s.settings.Password,
		PortsCount:     s.settings.PortsCount,
	}
	internalToExternalPorts, err := s.settings.PortForwarder.PortForward(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("port forwarding for the first time: %w", err)
	}

	s.portMutex.Lock()
	defer s.portMutex.Unlock()

	err = s.onNewPorts(ctx, internalToExternalPorts)
	if err != nil {
		return nil, err
	}

	keepPortCtx, keepPortCancel := context.WithCancel(context.Background())
	s.keepPortCancel = keepPortCancel
	runErrorCh := make(chan error)
	keepPortDoneCh := make(chan struct{})
	s.keepPortDoneCh = keepPortDoneCh

	readyCh := make(chan struct{})
	go func(ctx context.Context, portForwarder PortForwarder,
		obj utils.PortForwardObjects, readyCh chan<- struct{},
		runError chan<- error, doneCh chan<- struct{},
	) {
		defer close(doneCh)
		close(readyCh)
		err = portForwarder.KeepPortForward(ctx, obj)
		crashed := ctx.Err() == nil
		if !crashed { // stopped by Stop call
			return
		}
		s.startStopMutex.Lock()
		defer s.startStopMutex.Unlock()
		s.portMutex.Lock()
		defer s.portMutex.Unlock()
		_ = s.cleanup()
		runError <- err
	}(keepPortCtx, s.settings.PortForwarder, obj, readyCh, runErrorCh, keepPortDoneCh)
	<-readyCh

	return runErrorCh, nil
}

func (s *Service) onNewPorts(ctx context.Context, internalToExternalPorts map[uint16]uint16) (err error) {
	s.logger.Info(portPairsToString(internalToExternalPorts))

	externalPorts := slices.Collect(maps.Values(internalToExternalPorts))
	externalToInternalPorts := make(map[uint16]uint16, len(internalToExternalPorts))
	for internal, external := range internalToExternalPorts {
		externalToInternalPorts[external] = internal
	}
	slices.Sort(externalPorts)
	userRedirectionEnabled := !slices.Equal(s.settings.ListeningPorts, []uint16{0})
	for i, port := range externalPorts {
		internalPort := externalToInternalPorts[port]
		err = s.portAllower.SetAllowedPort(ctx, internalPort, s.settings.Interface)
		if err != nil {
			return fmt.Errorf("allowing port in firewall: %w", err)
		}

		var destinationPort uint16
		switch {
		case userRedirectionEnabled: // precedence over auto redirection
			destinationPort = s.settings.ListeningPorts[i]
		case port != internalPort: // auto redirection needed, source and destination ports differ
			destinationPort = port
		default:
			// No redirection needed, source and destination ports are the same.
			continue
		}

		err = s.portAllower.RedirectPort(ctx, s.settings.Interface, internalPort, destinationPort)
		if err != nil {
			return fmt.Errorf("redirecting port %d to %d in firewall: %w",
				internalPort, destinationPort, err)
		}
	}

	err = s.writePortForwardedFile(externalPorts)
	if err != nil {
		_ = s.cleanup()
		return fmt.Errorf("writing port file: %w", err)
	}

	s.ports = make([]uint16, len(internalToExternalPorts))
	copy(s.ports, externalPorts)

	if s.settings.UpCommand != "" {
		err = runCommand(ctx, s.cmder, s.logger, s.settings.UpCommand, externalPorts, s.settings.Interface)
		if err != nil {
			err = fmt.Errorf("running up command: %w", err)
			s.logger.Error(err.Error())
		}
	}

	return nil
}
