package service

import (
	"context"
	"fmt"
	"slices"
	"time"
)

func (s *Service) Stop() (err error) {
	s.startStopMutex.Lock()
	defer s.startStopMutex.Unlock()

	s.portMutex.RLock()
	serviceNotRunning := len(s.ports) == 0
	s.portMutex.RUnlock()
	if serviceNotRunning {
		// TODO replace with goservices.ErrAlreadyStopped
		return nil
	}

	s.logger.Info("stopping")

	s.keepPortCancel()
	<-s.keepPortDoneCh

	return s.cleanup()
}

func (s *Service) cleanup() (err error) {
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

	redirectionWasEnabled := !slices.Equal(s.settings.ListeningPorts, []uint16{0})
	for _, port := range s.ports {
		err = s.portAllower.RemoveAllowedPort(context.Background(), port)
		if err != nil {
			return fmt.Errorf("blocking previous port in firewall: %w", err)
		}

		if redirectionWasEnabled {
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
