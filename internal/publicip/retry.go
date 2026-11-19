package publicip

import (
	"time"

	"github.com/qdm12/gluetun/internal/backoff"
)

// Delay before the next attempt to fetch the public IP information following a
// failure. It doubles up to [maxRetryDelay]. The first failure usually follows
// a tunnel up by a few seconds, when the connection is not carrying traffic
// reliably yet, and the same fetch succeeds a moment later.
const defaultRetryDelay = 10 * time.Second

// Delay the doubling of [defaultRetryDelay] stops at, so a set of API servers
// answering nothing is not knocked at more than once every five minutes.
const maxRetryDelay = 5 * time.Minute

// retryState is where the run loop books the failures at fetching the public IP
// information: a [backoff.State] holds the delays, and the timer of the loop
// holds the retry pending. The channel of that timer is nil when there is
// nothing pending, so the select of the run loop ignores that case.
//
// Unlike port forwarding, the failures never run out. Nothing but a tunnel up
// fetches the information again, and that can be days later on a long lived
// connection; a fetch ending up going through is worth the wait, whatever the
// delay reached.
type retryState struct {
	timer    timer
	after    <-chan time.Time
	backoff  *backoff.State
	newTimer func(duration time.Duration) timer
}

func newRetryState(newTimer func(duration time.Duration) timer) retryState {
	const neverGiveUp = 0
	return retryState{
		backoff:  backoff.New(defaultRetryDelay, maxRetryDelay, neverGiveUp),
		newTimer: newTimer,
	}
}

// reset forgets the failures booked so far, which the tunnel coming up does: a
// fresh connection is a fresh chance, and the attempts to come are worth the
// default delay again rather than what a previous outage worked up to.
func (s *retryState) reset() {
	s.backoff.Reset()
}

// stop drops a retry pending, which a tunnel up does (it supersedes the attempt
// scheduled for the failure before it) and the VPN connection going down does
// (fetching with it down answers nothing but timeouts, see [Loop.ClearData]).
func (s *retryState) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer, s.after = nil, nil
}

// failure books one consecutive failure and arms the attempt the backoff finds
// it worth, with the delay that attempt is given.
func (s *retryState) failure() (booked backoff.Failure) {
	// Whatever this failure is worth, the attempt pending is off: the one below
	// takes over, and leaving the previous armed would fetch twice for it.
	s.stop()
	booked = s.backoff.Failure()
	s.timer = s.newTimer(booked.Delay)
	s.after = s.timer.C()
	return booked
}

// timeTimer is the [time.Timer] implementation of the [timer] interface.
type timeTimer struct {
	timer *time.Timer
}

func (t *timeTimer) C() <-chan time.Time { return t.timer.C }

func (t *timeTimer) Stop() { t.timer.Stop() }
