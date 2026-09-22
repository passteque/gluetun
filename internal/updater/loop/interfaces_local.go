package loop

import "time"

// timer is abstracted from time.Timer for tests.
type timer interface {
	// C returns the channel receiving the timed out event.
	C() <-chan time.Time
	// Reset resets the timer to the given duration.
	Reset(d time.Duration)
	// Stop stops the timer, consuming a timeout event already delivered.
	Stop()
}
