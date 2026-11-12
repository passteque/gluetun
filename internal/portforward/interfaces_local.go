package portforward

import "time"

// timer is abstracted from [time.Timer] for tests.
type timer interface {
	C() <-chan time.Time
	Stop()
}
