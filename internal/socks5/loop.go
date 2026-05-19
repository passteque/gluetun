package socks5

import (
	"context"
	"sync"
	"time"
)

type Loop struct {
	settings Settings

	mutex     sync.Mutex
	runCancel context.CancelFunc
	runDone   <-chan error
}

func NewLoop(settings Settings) *Loop {
	return &Loop{
		settings: settings,
	}
}

func (l *Loop) String() string {
	return "SOCKS5 server loop"
}

func (l *Loop) Start(_ context.Context) (runError <-chan error, err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	var runCtx context.Context
	runCtx, l.runCancel = context.WithCancel(context.Background())

	runDone := make(chan error)
	l.runDone = runDone
	runErrorCh := make(chan error)

	go run(runCtx, runDone, l.settings)

	return runErrorCh, nil
}

func run(ctx context.Context, done chan<- error, settings Settings) {
	defer close(done)
	logger := settings.Logger

	for ctx.Err() == nil {
		server := newServer(settings)
		errorCh, err := server.Start(ctx)
		if err != nil {
			logger.Warnf("failed starting SOCKS5 server: %s", err)
			waitBeforeRetry(ctx)
			continue
		}

		select {
		case <-ctx.Done():
			done <- server.Stop()
			return
		case err := <-errorCh:
			if ctx.Err() != nil {
				return
			}
			logger.Warnf("SOCKS5 server crashed: %s", err)
			waitBeforeRetry(ctx)
		}
	}
}

func (l *Loop) Stop() (err error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.runCancel()
	return <-l.runDone
}

func waitBeforeRetry(ctx context.Context) {
	const retryDelay = 10 * time.Second
	timer := time.NewTimer(retryDelay)
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
