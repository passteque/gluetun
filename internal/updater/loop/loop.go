package loop

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/updater"
)

type Updater interface {
	UpdateServers(ctx context.Context, providers []string, minRatio float64) (err error)
}

type Loop struct {
	state state
	// Objects
	updater Updater
	logger  Logger
	// Internal channels and locks
	loopLock sync.Mutex
	// Every request received on start and stop gets exactly one matching
	// notification back on running and stopped, so the loop is never
	// blocked on a notification. The sender of a request always reads the
	// matching notification, including the restarting ticker.
	start        chan struct{}
	running      chan models.LoopStatus
	stop         chan struct{}
	stopped      chan struct{}
	updateTicker chan struct{}
	backoffTime  time.Duration
	// Mock functions
	timeNow   func() time.Time
	timeSince func(time.Time) time.Duration
	newTimer  func() timer
}

const defaultBackoffTime = 5 * time.Second

type Logger interface {
	Info(s string)
	Warn(s string)
	Error(s string)
}

func NewLoop(settings settings.Updater, providers updater.Providers,
	storage updater.Storage, client *http.Client, logger Logger,
) *Loop {
	return &Loop{
		state: state{
			status:   constants.Stopped,
			settings: settings,
		},
		updater:      updater.New(client, storage, providers, logger, *settings.PreferDirectDownload),
		logger:       logger,
		start:        make(chan struct{}),
		running:      make(chan models.LoopStatus),
		stop:         make(chan struct{}),
		stopped:      make(chan struct{}),
		updateTicker: make(chan struct{}),
		timeNow:      time.Now,
		timeSince:    time.Since,
		backoffTime:  defaultBackoffTime,
		newTimer:     func() timer { return &timeTimer{timer: time.NewTimer(time.Hour)} },
	}
}

func (l *Loop) logAndWait(ctx context.Context, err error) {
	if err != nil {
		l.logger.Error(err.Error())
	}
	l.logger.Info("retrying in " + l.backoffTime.String())
	timer := time.NewTimer(l.backoffTime)
	l.backoffTime *= 2
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	}
}

func (l *Loop) Run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	// Release any caller waiting for a notification, should this loop exit
	// while one is waiting for it
	defer close(l.stopped)
	defer close(l.running)

	// crashed is true when the update to start was triggered by this loop
	// crashed after a failure, in which case no caller sent a start request
	// and so no caller is waiting to be notified that it is running
	crashed := false
	select {
	case <-l.start:
	case <-ctx.Done():
		return
	}

	for ctx.Err() == nil {
		notifyCaller := !crashed
		crashed = false

		updateCtx, updateCancel := context.WithCancel(ctx)

		settings := l.GetSettings()

		l.state.setStatusWithLock(constants.Running)

		errorCh := make(chan error)
		runWg := &sync.WaitGroup{}
		runWg.Add(1)
		go func() {
			defer runWg.Done()
			err := l.updater.UpdateServers(updateCtx, settings.Providers, settings.MinRatio)
			if updateCtx.Err() != nil {
				// The loop canceled this run, it is not listening for a result
				return
			}
			select {
			case errorCh <- err:
			case <-updateCtx.Done():
			}
		}()

		if notifyCaller {
			select {
			case l.running <- constants.Running:
			case <-ctx.Done():
			}
		}

		stayHere := true
		for stayHere {
			select {
			case <-ctx.Done():
				updateCancel()
				runWg.Wait()
				close(errorCh)
				return
			case <-l.start:
				l.logger.Info("starting")
				updateCancel()
				runWg.Wait()
				stayHere = false
			case <-l.stop:
				l.logger.Info("stopping")
				updateCancel()
				runWg.Wait()
				// Set the status before the notification below, since the
				// caller reads it once notified, and also because the
				// notification can be skipped at shutdown
				l.state.setStatusWithLock(constants.Stopped)
				select {
				case l.stopped <- struct{}{}:
				case <-ctx.Done():
				}
			case err := <-errorCh:
				if err == nil {
					// Reset the backoff time on success, so a later failed
					// update starts the exponential backoff over
					l.backoffTime = defaultBackoffTime
					l.state.setStatusWithLock(constants.Completed)
					continue
				}
				runWg.Wait()
				l.state.setStatusWithLock(constants.Crashed)
				l.logAndWait(ctx, err)
				crashed = true
				stayHere = false
			}
		}
		updateCancel()
		close(errorCh)
	}
}

func (l *Loop) RunRestartTicker(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	timer := l.newTimer()
	timer.Stop()
	timerIsStopped := true
	if period := *l.GetSettings().Period; period > 0 {
		timerIsStopped = false
		timer.Reset(period)
	}
	lastTick := time.Unix(0, 0)
	for {
		select {
		case <-ctx.Done():
			if !timerIsStopped {
				timer.Stop()
			}
			return
		case <-timer.C():
			lastTick = l.timeNow()
			started := l.atomicStart(ctx)
			if !started {
				return
			}
			timer.Reset(*l.GetSettings().Period)
		case <-l.updateTicker:
			if !timerIsStopped {
				timer.Stop()
			}
			timerIsStopped = true
			period := *l.GetSettings().Period
			if period == 0 {
				continue
			}
			var waited time.Duration
			if lastTick.UnixNano() > 0 {
				waited = l.timeSince(lastTick)
			}
			leftToWait := period - waited
			timer.Reset(leftToWait)
			timerIsStopped = false
		}
	}
}

// atomicStart requests the loop to start an update now. It reads back the
// notification the loop always sends per start request received, so the loop
// is never left blocked on it. It reports whether the request went through.
func (l *Loop) atomicStart(ctx context.Context) (started bool) {
	select {
	case l.start <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	_, notified := <-l.running
	return notified
}

// timeTimer is the time.Timer implementation of the ticker interface.
type timeTimer struct {
	timer *time.Timer
}

func (t *timeTimer) C() <-chan time.Time { return t.timer.C }

func (t *timeTimer) Reset(d time.Duration) { t.timer.Reset(d) }

func (t *timeTimer) Stop() {
	if !t.timer.Stop() {
		<-t.timer.C
	}
}
