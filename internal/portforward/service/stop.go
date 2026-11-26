package service

import (
	"context"
	"fmt"
	"time"
)

func (s *Service) Stop() (err error) {
	s.startStopMutex.Lock()
	defer s.startStopMutex.Unlock()

	s.portMutex.RLock()
	portsEmpty := len(s.ports) == 0
	s.portMutex.RUnlock()

	keepPortRunning := s.keepPortCancel != nil
	if keepPortRunning {
		// The keep port goroutine may have already exited after a crash.
		select {
		case <-s.keepPortDoneCh:
			keepPortRunning = false
		default:
		}
	}

	if portsEmpty && !keepPortRunning {
		// TODO replace with goservices.ErrAlreadyStopped
		// The keep port goroutine has crashed and cleaned the service up, and may
		// still be waiting to report its failure on a run error channel nobody
		// reads anymore. Nothing waits on the done channel from here, so the
		// context is canceled to release the goroutine instead of leaving it
		// parked on that send for the whole program life.
		if s.keepPortCancel != nil {
			s.keepPortCancel()
		}
		return nil
	}

	s.logger.Info("stopping")

	// The keep port goroutine may not be running if ports were set
	// at runtime by [Service.SetPortsForwarded] while port forwarding is
	// disabled, such as with providers without internal port
	// forwarding code support.
	if s.keepPortCancel != nil {
		s.keepPortCancel()
		// The keep port goroutine closes the done channel without waiting for the
		// start stop mutex held here, otherwise this wait could never be satisfied
		// by a goroutine crashing at the same time as this call.
		<-s.keepPortDoneCh
	}

	return s.cleanup()
}

func (s *Service) cleanup() (err error) {
	s.portMutex.Lock()
	defer s.portMutex.Unlock()

	if s.settings.DownCommand != "" {
		const downTimeout = 60 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), downTimeout)
		defer cancel()
		err = runCommand(ctx, s.cmder, s.logger, s.settings.DownCommand, s.ports, s.settings.Interface)
		if err != nil {
			err = fmt.Errorf("running down command: %w", err)
			s.logger.Error(err.Error())
		}
	}

	for _, port := range s.ports {
		err = s.portAllower.RemoveAllowedPort(context.Background(), port)
		if err != nil {
			return fmt.Errorf("blocking previous port in firewall: %w", err)
		}

		if s.settings.ListeningPort != 0 {
			ctx := context.Background()
			const listeningPort = 0 // 0 to clear the redirection
			err = s.portAllower.RedirectPort(ctx, s.settings.Interface, port, listeningPort)
			if err != nil {
				return fmt.Errorf("removing previous port redirection in firewall: %w", err)
			}
		}
	}

	s.ports = nil

	err = s.writePortForwardedFile(nil)
	if err != nil {
		return fmt.Errorf("clearing port file: %w", err)
	}

	return nil
}
