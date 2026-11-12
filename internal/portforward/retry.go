package portforward

import (
	"fmt"
	"time"
)

// Delay before the next try at running a port forwarding service following a
// failure. It doubles up to [maxRetryDelay], and goes back to this default when
// an update asks for a new service, and when a crashed service had run for
// [stableServiceRunTime].
const defaultRetryDelay = 5 * time.Second

// Delay the doubling of [defaultRetryDelay] stops at, so a server which will
// never support port forwarding is not retried at an unreasonable rate.
const maxRetryDelay = 5 * time.Minute

// Consecutive failures tolerated before the run gives up on port forwarding,
// which is close to two hours of waiting once the delay reached its maximum.
// Only consecutive failures add up, since an accepted update and a stable
// service run reset the count. The run ends because only a restart of the
// program asks the provider for another VPN server. This and the two delays are
// not local to the code booking a failure, since the test declares one
// expectation per attempt and announces the delay of each one.
const maxRetryAttempts = 30

// Uptime after which a crashed port forwarding service is considered to have
// run well enough for the failures it survived to be forgotten. A service which
// crashes as fast as it started does not reach it, and keeps escalating its
// retry delay until the run gives up.
const stableServiceRunTime = 5 * time.Minute

// retryState is the backoff of the run loop: the delay to wait before the next
// service start, the timer it is armed with, the count of consecutive failures
// which decides when the run has to end, and the timer factory. A pending retry
// is held by the timer, and its channel is nil when there is nothing pending,
// so the select of the run loop ignores that case.
type retryState struct {
	timer    timer
	after    <-chan time.Time
	delay    time.Duration
	attempts int
	newTimer func(duration time.Duration) timer
}

func newRetryState(newTimer func(duration time.Duration) timer) retryState {
	return retryState{
		delay:    defaultRetryDelay,
		newTimer: newTimer,
	}
}

func (s *retryState) reset() {
	s.delay = defaultRetryDelay
	s.attempts = 0
}

// stop drops a pending retry, which both a restart of the service and the end
// of the run do: nothing is left to wake up for a failure already dealt with.
func (s *retryState) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer, s.after = nil, nil
}

// failure books one consecutive failure, arms the next service start with the
// current delay and doubles that delay, and gives back the error to report.
// Once too many failures piled up nothing is armed, and giveUp tells the run
// loop to end.
func (s *retryState) failure(failed error) (giveUp bool, reported error) {
	s.attempts++
	if s.attempts >= maxRetryAttempts {
		return true, fmt.Errorf("%w - giving up after %d consecutive failed attempts", failed, s.attempts)
	}
	reported = fmt.Errorf("%w - retrying in %s (attempt %d/%d)",
		failed, s.delay, s.attempts, maxRetryAttempts)
	s.timer = s.newTimer(s.delay)
	s.after = s.timer.C()
	const delayFactor = 2
	s.delay = min(s.delay*delayFactor, maxRetryDelay)
	return false, reported
}

// reportFailure books one failure at running a port forwarding service, and
// tells about it to the update caller when one is waiting, or to the logger
// otherwise. Once too many consecutive failures piled up, no new attempt is
// armed and the error goes back to the program, which has to restart the whole
// thing: only a new VPN session asks the provider for another server, which is
// what a server refusing to forward a port needs. The run loop is told to end.
func (l *Loop) reportFailure(retries *retryState, failed error, updateReceived bool,
	updateResult chan<- error, runErrorCh chan<- error,
) (endRun bool) {
	giveUp, reported := retries.failure(failed)
	switch {
	case updateReceived:
		// The caller waits for the outcome of the update it asked for, whatever
		// the run does next.
		updateResult <- reported
	case !giveUp:
		l.logger.Error(reported.Error())
	}
	if giveUp {
		runErrorCh <- reported
	}
	return giveUp
}

// timeTimer is the [time.Timer] implementation of the [timer] interface.
type timeTimer struct {
	timer *time.Timer
}

func (t *timeTimer) C() <-chan time.Time { return t.timer.C }

func (t *timeTimer) Stop() { t.timer.Stop() }
