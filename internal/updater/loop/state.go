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
		l.loopLock.Lock()
		defer l.loopLock.Unlock()
		l.state.status = constants.Starting
		l.state.statusMu.Unlock()
		l.start <- struct{}{}

		newStatus := constants.Starting // for canceled context
		select {
		case <-ctx.Done():
		case newStatus = <-l.running:
		}
		l.state.statusMu.Lock()
		l.state.status = newStatus
		return newStatus.String(), nil
	case constants.Stopped:
		switch existingStatus {
		case constants.Stopped, constants.Stopping, constants.Starting, constants.Crashed:
			return fmt.Sprintf("already %s", existingStatus), nil
		}
		l.loopLock.Lock()
		defer l.loopLock.Unlock()
		l.state.status = constants.Stopping
		l.state.statusMu.Unlock()
		l.stop <- struct{}{}

		newStatus := constants.Stopping // for canceled context
		select {
		case <-ctx.Done():
		case <-l.stopped:
			newStatus = constants.Stopped
		}
		l.state.statusMu.Lock()
		l.state.status = newStatus
		return status.String(), nil
	default:
		return "", fmt.Errorf("invalid status: %s: it can only be one of: %s, %s",
			status, constants.Running, constants.Stopped)
	}
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
