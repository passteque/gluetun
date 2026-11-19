package loop

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

type state struct {
	status   models.LoopStatus
	settings settings.Updater
	statusMu sync.RWMutex
	periodMu sync.RWMutex
}

func (s *state) setStatusWithLock(status models.LoopStatus) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	s.status = status
}

func (l *Loop) GetStatus() (status models.LoopStatus) {
	l.state.statusMu.RLock()
	defer l.state.statusMu.RUnlock()
	return l.state.status
}

func (l *Loop) SetStatus(ctx context.Context, status models.LoopStatus) (outcome string, err error) {
	l.state.statusMu.Lock()
	defer l.state.statusMu.Unlock()
	existingStatus := l.state.status

	switch status {
	case constants.Running:
		switch existingStatus {
		case constants.Starting, constants.Running, constants.Stopping, constants.Crashed:
			return fmt.Sprintf("already %s", existingStatus), nil
		}
		return transitionStatus(ctx, l, existingStatus, constants.Starting, l.start, l.running), nil
	case constants.Stopped:
		switch existingStatus {
		case constants.Stopped, constants.Stopping, constants.Starting, constants.Crashed:
			return fmt.Sprintf("already %s", existingStatus), nil
		}
		return transitionStatus(ctx, l, existingStatus, constants.Stopping, l.stop, l.stopped), nil
	default:
		return "", fmt.Errorf("invalid status: %s: it can only be one of: %s, %s",
			status, constants.Running, constants.Stopped)
	}
}

// transitionStatus sets the transition status, requests the transition from
// the loop, waits for the loop to perform it, and returns the resulting status.
// The request can be abandoned with the context, in which case the previous
// status is restored. Once the loop received the request though, the matching
// notification is always read back, since the loop sends exactly one
// notification per request received and would otherwise be left blocked.
func transitionStatus[notificationType any](ctx context.Context, l *Loop,
	existingStatus models.LoopStatus, transitionStatus models.LoopStatus,
	request chan<- struct{}, notification <-chan notificationType,
) (outcome string) {
	l.loopLock.Lock()
	defer l.loopLock.Unlock()
	l.state.status = transitionStatus
	l.state.statusMu.Unlock()

	requestSent := false
	select {
	case <-ctx.Done():
	case request <- struct{}{}:
		requestSent = true
		// Read back the notification the loop always sends per request
		// received, so the loop is never left blocked on it. The loop also
		// closes the channel if it exits, so this never waits forever.
		<-notification
	}
	l.state.statusMu.Lock()
	if !requestSent {
		// The request never reached the loop, so revert to the
		// status the loop was in before this call
		l.state.status = existingStatus
	}
	return l.state.status.String()
}

func (l *Loop) GetSettings() (settings settings.Updater) {
	l.state.periodMu.RLock()
	defer l.state.periodMu.RUnlock()
	return l.state.settings
}

func (l *Loop) SetSettings(settings settings.Updater) (outcome string) {
	l.state.periodMu.Lock()
	defer l.state.periodMu.Unlock()
	settingsUnchanged := reflect.DeepEqual(settings, l.state.settings)
	if settingsUnchanged {
		return "settings left unchanged"
	}
	l.state.settings = settings
	l.updateTicker <- struct{}{}
	return "settings updated"
}
