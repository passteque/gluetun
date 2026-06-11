package loopstate

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

// ApplyStatus sends signals to the running loop depending on the
// current status and status requested, such that its next status
// matches the requested one. It is thread safe and a synchronous call
// since it waits to the loop to fully change its status.
func (s *State) ApplyStatus(ctx context.Context, status models.LoopStatus) (
	outcome string, err error,
) {
	// prevent simultaneous loop changes by restricting
	// multiple ApplyStatus calls to run sequentially.
	s.loopMu.Lock()
	defer s.loopMu.Unlock()

	// not a read lock as we want to modify it eventually in
	// the code below before any other call.
	s.statusMu.Lock()
	existingStatus := s.status

	switch status {
	case constants.Running:
		switch existingStatus {
		case constants.Stopped, constants.Completed:
		default:
			s.statusMu.Unlock()
			return "already " + existingStatus.String(), nil
		}

		s.status = constants.Starting
		s.statusMu.Unlock()
		s.start <- struct{}{}

		// Wait for the loop to react to the start signal
		newStatus := constants.Starting // for canceled context
		select {
		case <-ctx.Done():
		case newStatus = <-s.running:
		}

		s.SetStatus(newStatus)

		return newStatus.String(), nil
	case constants.Stopped:
		if existingStatus != constants.Running {
			s.statusMu.Unlock()
			return "already " + existingStatus.String(), nil
		}

		s.status = constants.Stopping
		s.statusMu.Unlock()
		s.stop <- struct{}{}

		// Wait for the loop to react to the stop signal
		newStatus := constants.Stopping // for canceled context
		select {
		case <-ctx.Done():
		case <-s.stopped:
			newStatus = constants.Stopped
		}
		s.SetStatus(newStatus)

		return newStatus.String(), nil
	default:
		s.statusMu.Unlock()
		return "", fmt.Errorf("invalid status: %s: it can only be one of: %s, %s",
			status, constants.Running, constants.Stopped)
	}
}
