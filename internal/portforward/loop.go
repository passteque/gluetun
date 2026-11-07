package portforward

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/portforward/service"
)

type Loop struct {
	// State
	settings      Settings
	settingsMutex sync.RWMutex
	// service is replaced by the run goroutine on every update, and called by
	// the API methods from the HTTP handler goroutines. The mutex is held for
	// the whole execution of those methods, so a service is never replaced nor
	// stopped while one of its calls is in progress.
	service      Service
	serviceMutex sync.Mutex
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
				Enabled:        settings.Enabled,
				Filepath:       *settings.Filepath,
				UpCommand:      *settings.UpCommand,
				DownCommand:    *settings.DownCommand,
				ListeningPorts: settings.ListeningPorts,
				PortsCount:     settings.PortsCount,
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

	go func() {
		// Canceled when the loop is over, whatever the reason, so a caller
		// waiting in UpdateWith is released instead of blocked forever.
		defer l.runCancel()
		l.run(l.runCtx, runDone, runErrorCh, updateTrigger, updateResult)
	}()

	return runErrorCh, nil
}

func (l *Loop) run(runCtx context.Context, runDone chan<- struct{},
	runErrorCh chan<- error, updateTrigger <-chan Settings,
	updateResult chan<- error,
) {
	defer close(runDone)

	var serviceRunError <-chan error
	var retryAfter <-chan time.Time
	const retryDelay = 5 * time.Second
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
		case <-retryAfter:
		}
		// Any pending retry is superseded by the restart below
		retryAfter = nil

		previousService := l.currentService()
		if previousService != nil {
			err := previousService.Stop()
			if err != nil {
				runErrorCh <- fmt.Errorf("stopping previous service: %w", err)
				return
			}
		}

		serviceSettings := l.settings.Service.Copy()
		// Only enable port forward if the VPN tunnel is up
		*serviceSettings.Enabled = *serviceSettings.Enabled && *l.settings.VPNIsUp

		newService := service.New(serviceSettings, l.routing, l.client,
			l.portAllower, l.logger, l.cmder, l.uid, l.gid)
		l.setService(newService)

		var err error
		serviceRunError, err = newService.Start(runCtx)
		if err != nil {
			err = fmt.Errorf("starting port forwarding service: %w - retrying in %s", err, retryDelay)
			retryAfter = time.After(retryDelay)
			if !updateReceived {
				// Otherwise the error is sent back to the update caller,
				// which logs it.
				l.logger.Error(err.Error())
			}
		}
		if updateReceived {
			// Signal to the Update call that the service has started,
			// and if it failed to start.
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

	l.serviceMutex.Lock()
	defer l.serviceMutex.Unlock()

	if l.service == nil {
		return nil
	}
	return l.service.Stop()
}

func (l *Loop) GetPortsForwarded() (ports []uint16) {
	l.serviceMutex.Lock()
	defer l.serviceMutex.Unlock()

	if l.service == nil {
		return nil
	}
	return l.service.GetPortsForwarded()
}

func (l *Loop) SetPortsForwarded(ports []uint16) (err error) {
	l.serviceMutex.Lock()
	defer l.serviceMutex.Unlock()

	if l.service == nil {
		return errors.New("port forwarding service not started")
	}
	return l.service.SetPortsForwarded(l.runCtx, ports)
}

// currentService returns the service of the current run. It is nil as long as
// the loop has not started one, and stays the stopped one once the loop has
// stopped, since the Stop call does not clear the field.
func (l *Loop) currentService() Service { //nolint:ireturn
	l.serviceMutex.Lock()
	defer l.serviceMutex.Unlock()
	return l.service
}

// setService replaces the service of the current run, the run goroutine being
// the only one to call it once the previous service has been stopped.
func (l *Loop) setService(newService Service) {
	l.serviceMutex.Lock()
	defer l.serviceMutex.Unlock()
	l.service = newService
}

func ptrTo[T any](value T) *T {
	return &value
}
