package service

import (
	"context"
	"fmt"

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
	}
	ports, err := s.settings.PortForwarder.PortForward(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("port forwarding for the first time: %w", err)
	}

	s.logger.Info(portsToString(ports))

	for _, port := range ports {
		err = s.portAllower.SetAllowedPort(ctx, port, s.settings.Interface)
		if err != nil {
			return nil, fmt.Errorf("allowing port in firewall: %w", err)
		}

		if s.settings.ListeningPort != 0 {
			err = s.portAllower.RedirectPort(ctx, s.settings.Interface, port, s.settings.ListeningPort)
			if err != nil {
				return nil, fmt.Errorf("redirecting port in firewall: %w", err)
			}
		}
	}

	err = s.writePortForwardedFile(ports)
	if err != nil {
		_ = s.cleanup()
		return nil, fmt.Errorf("writing port file: %w", err)
	}

	s.portMutex.Lock()
	s.ports = ports
	s.portMutex.Unlock()

	if s.settings.UpCommand != "" {
		err = runCommand(ctx, s.cmder, s.logger, s.settings.UpCommand, ports, s.settings.Interface)
		if err != nil {
			err = fmt.Errorf("running up command: %w", err)
			s.logger.Error(err.Error())
		}
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
		close(readyCh)
		err := portForwarder.KeepPortForward(ctx, obj)
		crashed := ctx.Err() == nil
		// The done channel is closed without waiting for the start stop mutex.
		// Stop holds that mutex for the whole of its call and waits on the channel
		// while holding it: closing it once the mutex is taken would leave Stop
		// waiting for a goroutine waiting for the mutex it holds itself, and the
		// service could never be stopped. From here on the goroutine only reaches
		// the service through the start stop mutex Stop holds, and gives up on its
		// own cleanup once Stop has canceled the context, so the service is cleaned
		// up exactly once, by whoever holds that mutex. Closing the channel before the
		// report is handed over below also tells the port forwarding loop, which
		// answers that report by stopping the service, that there is nothing left
		// for that Stop call to do.
		close(doneCh)
		if !crashed { // stopped by Stop call
			return
		}
		s.startStopMutex.Lock()
		if ctx.Err() == nil { // no Stop call took over while waiting for the mutex
			_ = s.cleanup()
		}
		s.startStopMutex.Unlock()

		// The report is made without the mutexes held, and given up on once the
		// service is stopped. The port forwarding loop reads this channel while
		// it runs, but it leaves the service behind when it stops on a fatal
		// error: a send holding the start stop mutex forever prevents the
		// service from ever being stopped, since Stop waits for the very
		// goroutine reporting the crash. Nothing waits on the done channel once it
		// is closed, so Stop releases this send by canceling the context instead.
		select {
		case runError <- err:
		case <-ctx.Done():
		}
	}(keepPortCtx, s.settings.PortForwarder, obj, readyCh, runErrorCh, keepPortDoneCh)
	<-readyCh

	return runErrorCh, nil
}
