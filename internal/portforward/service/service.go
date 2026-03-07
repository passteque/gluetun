package service

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
)

type Service struct {
	// State
	portMutex sync.RWMutex
	ports     []uint16
	// Fixed parameters
	settings Settings
	puid     int
	pgid     int
	// Fixed injected objects
	routing     Routing
	client      *http.Client
	portAllower PortAllower
	logger      Logger
	cmder       Cmder
	// Internal channels and locks
	startStopMutex sync.Mutex
	keepPortCancel context.CancelFunc
	keepPortDoneCh <-chan struct{}
}

func New(settings Settings, routing Routing, client *http.Client,
	portAllower PortAllower, logger Logger, cmder Cmder, puid, pgid int,
) *Service {
	return &Service{
		// Fixed parameters
		settings: settings,
		puid:     puid,
		pgid:     pgid,
		// Fixed injected objects
		routing:     routing,
		client:      client,
		portAllower: portAllower,
		logger:      logger,
		cmder:       cmder,
	}
}

func (s *Service) GetPortsForwarded() (ports []uint16) {
	s.portMutex.RLock()
	defer s.portMutex.RUnlock()
	ports = make([]uint16, len(s.ports))
	copy(ports, s.ports)
	return ports
}

func (s *Service) SetPortsForwarded(ctx context.Context, ports []uint16) (err error) {
	s.startStopMutex.Lock()
	defer s.startStopMutex.Unlock()
	s.portMutex.Lock()
	defer s.portMutex.Unlock()

	slices.Sort(ports)
	if slices.Equal(s.ports, ports) {
		return nil
	}

	err = s.cleanup()
	if err != nil {
		return fmt.Errorf("cleaning up: %w", err)
	}

	err = s.onNewPorts(ctx, ports)
	if err != nil {
		return fmt.Errorf("handling new ports: %w", err)
	}

	s.logger.Info("updated: " + portsToString(s.ports))

	return nil
}
