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
	loopLock     sync.Mutex
	start        chan struct{}
	running      chan models.LoopStatus
	stop         chan struct{}
	stopped      chan struct{}
	updateTicker chan struct{}
	backoffTime  time.Duration
	// Mock functions
	timeNow   func() time.Time
	timeSince func(time.Time) time.Duration
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
	crashed := false
	select {
	case <-l.start:
	case <-ctx.Done():
		return
	}

	for ctx.Err() == nil {
		updateCtx, updateCancel := context.WithCancel(ctx)

		settings := l.GetSettings()

		errorCh := make(chan error)
		runWg := &sync.WaitGroup{}
		runWg.Add(1)
		go func() {
			defer runWg.Done()
			err := l.updater.UpdateServers(updateCtx, settings.Providers, settings.MinRatio)
			if err != nil {
				if updateCtx.Err() == nil {
					errorCh <- err
				}
				return
			}
			l.state.setStatusWithLock(constants.Completed)
		}()

		if !crashed {
			l.running <- constants.Running
			crashed = false
		} else {
			l.backoffTime = defaultBackoffTime
			l.state.setStatusWithLock(constants.Running)
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
				l.stopped <- struct{}{}
			case err := <-errorCh:
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
	timer := time.NewTimer(time.Hour)
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
			if !timerIsStopped && !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
			lastTick = l.timeNow()
			l.start <- struct{}{}
			timer.Reset(*l.GetSettings().Period)
		case <-l.updateTicker:
			if !timerIsStopped && !timer.Stop() {
				<-timer.C
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
