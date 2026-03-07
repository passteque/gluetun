package portforward

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/portforward/service"
)

type Loop struct {
	// State
	settings      Settings
	settingsMutex sync.RWMutex
	service       Service
	// Fixed injected objects
	routing     Routing
	client      *http.Client
	portAllower PortAllower
	logger      Logger
	cmder       Cmder
	// Fixed parameters
	uid, gid int
	// Internal channels and locks
	// runCtx is used to detect when the loop has exited
	// when performing an update
	runCtx        context.Context //nolint:containedctx
	runCancel     context.CancelFunc
	runDone       <-chan struct{}
	updateTrigger chan<- Settings
	updatedResult <-chan error
}

func NewLoop(settings settings.PortForwarding, routing Routing,
	client *http.Client, portAllower PortAllower,
	logger Logger, cmder Cmder, uid, gid int,
) *Loop {
	return &Loop{
		settings: Settings{
			VPNIsUp: ptrTo(false),
			Service: service.Settings{
				Enabled:       settings.Enabled,
				Filepath:      *settings.Filepath,
				UpCommand:     *settings.UpCommand,
				DownCommand:   *settings.DownCommand,
				ListeningPort: *settings.ListeningPort,
			},
		},
		routing:     routing,
		client:      client,
		portAllower: portAllower,
		logger:      logger,
		cmder:       cmder,
		uid:         uid,
		gid:         gid,
	}
}

func (l *Loop) String() string {
	return "port forwarding loop"
}

func (l *Loop) Start(_ context.Context) (runError <-chan error, _ error) {
	l.runCtx, l.runCancel = context.WithCancel(context.Background())
	runDone := make(chan struct{})
	l.runDone = runDone

	updateTrigger := make(chan Settings)
	l.updateTrigger = updateTrigger
	updateResult := make(chan error)
	l.updatedResult = updateResult
	runErrorCh := make(chan error)

	go l.run(l.runCtx, runDone, runErrorCh, updateTrigger, updateResult)

	return runErrorCh, nil
}

func (l *Loop) run(runCtx context.Context, runDone chan<- struct{},
	runErrorCh chan<- error, updateTrigger <-chan Settings,
	updateResult chan<- error,
) {
	defer close(runDone)

	var serviceRunError <-chan error
	for {
		updateReceived := false
		select {
		case <-runCtx.Done():
			// Stop call takes care of stopping the service
			return
		case partialUpdate := <-updateTrigger:
			updatedSettings, err := l.settings.updateWith(partialUpdate, *l.settings.VPNIsUp)
			if err != nil {
				updateResult <- err
				continue
			}
			updateReceived = true
			l.settingsMutex.Lock()
			l.settings = updatedSettings
			l.settingsMutex.Unlock()
		case err := <-serviceRunError:
			l.logger.Error(err.Error())
		}

		firstRun := serviceRunError == nil
		if !firstRun {
			err := l.service.Stop()
			if err != nil {
				runErrorCh <- fmt.Errorf("stopping previous service: %w", err)
				return
			}
		}

		serviceSettings := l.settings.Service.Copy()
		// Only enable port forward if the VPN tunnel is up
		*serviceSettings.Enabled = *serviceSettings.Enabled && *l.settings.VPNIsUp

		l.service = service.New(serviceSettings, l.routing, l.client,
			l.portAllower, l.logger, l.cmder, l.uid, l.gid)

		var err error
		serviceRunError, err = l.service.Start(runCtx)
		if updateReceived {
			// Signal to the Update call that the service has started
			// and if it failed to start.
			if err != nil {
				err = fmt.Errorf("starting port forwarding service: %w", err)
			}
			updateResult <- err
		}
	}
}

func (l *Loop) UpdateWith(partialUpdate Settings) (err error) {
	select {
	case l.updateTrigger <- partialUpdate:
		select {
		case err = <-l.updatedResult:
			return err
		case <-l.runCtx.Done():
			return l.runCtx.Err()
		}
	case <-l.runCtx.Done():
		// loop has been stopped, no update can be done
		return l.runCtx.Err()
	}
}

func (l *Loop) Stop() (err error) {
	l.runCancel()
	<-l.runDone

	if l.service != nil {
		return l.service.Stop()
	}
	return nil
}

func (l *Loop) GetPortsForwarded() (ports []uint16) {
	if l.service == nil {
		return nil
	}
	return l.service.GetPortsForwarded()
}

var ErrServiceNotStarted = errors.New("port forwarding service not started")

func (l *Loop) SetPortsForwarded(ports []uint16) (err error) {
	if l.service == nil {
		return fmt.Errorf("%w", ErrServiceNotStarted)
	}

	return l.service.SetPortsForwarded(l.runCtx, ports)
}

func ptrTo[T any](value T) *T {
	return &value
}
