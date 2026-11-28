package httpproxy

import (
	"context"

	"github.com/qdm12/gluetun/internal/constants"
)

func (l *Loop) Run(ctx context.Context, done chan<- struct{}) {
	defer close(done)

	if !*l.state.GetSettings().Enabled {
		select {
		case <-l.start:
		case <-ctx.Done():
			return
		}
	}

	for ctx.Err() == nil {
		runCtx, runCancel := context.WithCancel(ctx)

		settings := l.state.GetSettings()
		server := New(runCtx, settings.ListeningAddress, l.logger,
			*settings.Stealth, *settings.Log, *settings.User,
			*settings.Password, settings.ReadHeaderTimeout)

		errorCh := make(chan error)
		go server.Run(runCtx, errorCh)

		// TODO stable timer, check Shadowsocks
		if l.userTrigger {
			l.running <- constants.Running
			l.userTrigger = false
		} else {
			l.backoffTime = defaultBackoffTime
			l.statusManager.SetStatus(constants.Running)
		}

		stayHere := true
		for stayHere {
			select {
			case <-ctx.Done():
				runCancel()
				<-errorCh
				close(errorCh)
				return
			case <-l.start:
				l.userTrigger = true
				l.logger.Info("starting")
				runCancel()
				<-errorCh
				close(errorCh)
				stayHere = false
			case <-l.stop:
				l.userTrigger = true
				l.logger.Info("stopping")
				runCancel()
				<-errorCh
				// Do not close errorCh or this for loop won't work
				l.stopped <- struct{}{}
			case err := <-errorCh:
				close(errorCh)
				l.statusManager.SetStatus(constants.Crashed)
				l.logAndWait(ctx, err)
				stayHere = false
			}
		}
		runCancel() // repetition for linter only
	}
}
