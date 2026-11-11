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

// ErrServiceNotRunning is given back to a [Loop.SetPortsForwarded] call asking for
// ports while no port forwarding service runs, which happens in the short time
// before the run loop starts the first one. The loop starts one on its own,
// so the caller can try again later.
var ErrServiceNotRunning = errors.New("port forwarding service is not running, try again later")

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
	// Mock functions
	newTimer func(duration time.Duration) timer
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
		newTimer: func(duration time.Duration) timer {
			return &timeTimer{timer: time.NewTimer(duration)}
		},
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
	// A retry is pending when retryTimer is not nil. Both it and its channel
	// are set and cleared together, the channel being nil when there is no
	// pending retry, so the select below ignores that case.
	var retryTimer timer
	var retryAfter <-chan time.Time
	// A failed service start is retried after a doubling delay, capped so a
	// server which will never support port forwarding does not fill the logs
	// and call the provider API every few seconds for the whole tunnel
	// session. The delay goes back to its default once the service starts, and
	// when an update asks for a new service.
	const defaultRetryDelay = 5 * time.Second
	const maxRetryDelay = 5 * time.Minute
	retryDelay := defaultRetryDelay
	// armRetry schedules the next service start with the current retry delay,
	// and doubles that delay for the next failure, capped at the maximum.
	armRetry := func() {
		retryTimer = l.newTimer(retryDelay)
		retryAfter = retryTimer.C()
		retryDelay *= 2
		retryDelay = min(retryDelay, maxRetryDelay)
	}
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
			// New settings are a reason to try again right away, whatever the
			// previous failures were.
			retryDelay = defaultRetryDelay
			l.settingsMutex.Lock()
			l.settings = updatedSettings
			l.settingsMutex.Unlock()
		case err := <-serviceRunError:
			// Restarting right away would call the provider API as fast as the
			// service keeps crashing, so a crash waits for a retry delay too,
			// like a failed start. An accepted update still restarts the service
			// right away, whatever the delay reached.
			err = fmt.Errorf("keeping port forwarded: %w - retrying in %s", err, retryDelay)
			armRetry()
			l.logger.Error(err.Error())
			continue
		case <-retryAfter:
			// The pending retry is over, the timer has nothing left to stop
			retryTimer, retryAfter = nil, nil
		}
		if retryTimer != nil {
			// Any pending retry is superseded by the restart below. Stopping it
			// prevents a later restart of a working service, remapping the port
			// forwarded for the failure it was scheduled for.
			retryTimer.Stop()
			retryTimer, retryAfter = nil, nil
		}

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
			armRetry()
			if !updateReceived {
				// Otherwise the error is sent back to the update caller,
				// which logs it.
				l.logger.Error(err.Error())
			}
		} else {
			// Reset the delay on success, so a later failure of an otherwise
			// working service does not inherit a backoff of minutes.
			retryDelay = defaultRetryDelay
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
		return fmt.Errorf("%w", ErrServiceNotRunning)
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

// timeTimer is the time.Timer implementation of the timer interface.
type timeTimer struct {
	timer *time.Timer
}

func (t *timeTimer) C() <-chan time.Time { return t.timer.C }

func (t *timeTimer) Stop() { t.timer.Stop() }

func ptrTo[T any](value T) *T {
	return &value
}
