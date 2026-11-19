// Package backoff decides when to try again an operation which keeps failing,
// from the delay the next attempt is worth and the number of consecutive
// failures tolerated, without saying anything about what the attempt is, how it
// is scheduled, or what giving up means.
package backoff

import "time"

// State is the backoff of a single operation: the delay its next attempt is
// worth, and how many consecutive failures it booked. It is not safe for
// concurrent use, an operation being booked by the single goroutine running it.
type State struct {
	// initial is the delay of the first failure and the delay a reset goes back
	// to; maximum is the delay the doubling stops at; maxFailures is the number
	// of consecutive failures tolerated before giving up, or a value <= 0 when
	// the failures never run out.
	initial     time.Duration
	maximum     time.Duration
	maxFailures int
	// delay is the delay the next failure is worth, doubled by every failure.
	delay time.Duration
	// failures counts the failures booked since the last reset.
	failures int
}

// Failure is what one booked failure is worth, and is what a caller logs and
// schedules an attempt with.
type Failure struct {
	// Delay is how long the next attempt waits, the delay of this failure being
	// the one before it doubled, held at the maximum given to [New].
	Delay time.Duration
	// Attempts is the number of consecutive failures this one makes, and Max the
	// number tolerated, so a log line announcing a retry has them both.
	Attempts int
	Max      int
	// GiveUp is true once Attempts reaches Max: nothing is scheduled anymore and
	// the caller decides what ending the operation means. It stays true until the
	// state is [State.Reset].
	GiveUp bool
}

// New is the backoff of an operation retrying at the initial delay, doubling it
// after every failure up to the maximum, and giving up once maxFailures
// consecutive failures piled up. A maximum below the initial delay is held at it,
// and a maxFailures of 0 or less means the failures never run out.
func New(initial, maximum time.Duration, maxFailures int) *State {
	if maximum < initial {
		maximum = initial
	}
	return &State{
		initial:     initial,
		maximum:     maximum,
		maxFailures: maxFailures,
		delay:       initial,
	}
}

// Reset forgets the failures booked so far, which is what an operation starting
// from a fresh slate does: a new attempt is worth the initial delay again.
func (s *State) Reset() {
	s.delay = s.initial
	s.failures = 0
}

// Failure books one failure and gives back what it is worth. The delays double
// from the initial one up to the maximum, whatever the failures were, and
// [Failure.GiveUp] answers whether the state has had enough of them.
func (s *State) Failure() Failure {
	s.failures++
	const failureFactor = 2
	delay := s.delay
	s.delay = min(s.delay*failureFactor, s.maximum)
	return Failure{
		Delay:    delay,
		Attempts: s.failures,
		Max:      s.maxFailures,
		GiveUp:   s.maxFailures > 0 && s.failures >= s.maxFailures,
	}
}
