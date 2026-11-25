package vpn

import (
	"context"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

func ptrTo[T any](value T) *T { return &value }

// waitForError waits 100ms for an error in the waitError channel.
func (l *Loop) waitForError(ctx context.Context,
	waitError chan error,
) (err error) {
	const waitDurationForError = 100 * time.Millisecond
	timer := time.NewTimer(waitDurationForError)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return ctx.Err()
	case <-timer.C:
		return nil
	case err := <-waitError:
		close(waitError)
		if !timer.Stop() {
			<-timer.C
		}
		return err
	}
}

func (l *Loop) crashed(ctx context.Context, err error) {
	l.signalOrSetStatus(constants.Crashed)
	l.logAndWait(ctx, err)
}

func (l *Loop) signalOrSetStatus(status models.LoopStatus) {
	if l.userTrigger {
		l.userTrigger = false
		select {
		case l.running <- status:
		default: // receiver calling ApplyStatus dropped out
		}
	} else {
		l.statusManager.SetStatus(status)
	}
}

func (l *Loop) logAndWait(ctx context.Context, err error) {
	if err != nil {
		l.logger.Error(err.Error())
	}
	backoff := l.getAndAdvanceBackoff()
	l.logger.Info("retrying in " + backoff.String())
	timer := time.NewTimer(backoff)
	select {
	case <-timer.C:
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	}
}
