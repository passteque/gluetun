package portforward

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Test_retryState_failure checks what a booked failure announces and arms, and
// that a failure never leaves the retry of the failure before it pending. The
// run loop is woken by the channel of the armed timer only, so a retry left
// pending behind would start a service the loop has no memory of.
func Test_retryState_failure(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// failures is how many failures are booked one after the other on the
		// same state, without anything resetting it in between.
		failures int
		// givenUp is true when the last failure ends the run instead of waiting
		// for another attempt.
		givenUp bool
		// delays are the delays each armed timer is given, nil when there are too
		// many of them to list, which the give up case is.
		delays []time.Duration
	}{
		"first_failure_only": {
			failures: 1,
			delays:   []time.Duration{5 * time.Second},
		},
		"second_failure_doubles_the_delay": {
			failures: 2,
			delays:   []time.Duration{5 * time.Second, 10 * time.Second},
		},
		"give_up_after_the_maximum_of_failures": {
			failures: maxRetryAttempts,
			givenUp:  true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			failed := errors.New("tcp and udp external ports differ")
			// Every failure arms a timer, except the one giving up; every failure
			// stops the retry pending from the one before it, except the first one,
			// which finds nothing pending.
			armedCount := testCase.failures
			if testCase.givenUp {
				armedCount--
			}
			retryTimer := NewMocktimer(ctrl)
			ticks := make(chan time.Time)
			retryTimer.EXPECT().C().Return(ticks).Times(armedCount)
			if testCase.failures > 1 {
				retryTimer.EXPECT().Stop().Times(testCase.failures - 1)
			}

			var armedDelays []time.Duration
			retries := newRetryState(func(delay time.Duration) timer {
				armedDelays = append(armedDelays, delay)
				return retryTimer
			})

			var (
				reported error
				giveUp   bool
			)
			for range testCase.failures {
				giveUp, reported = retries.failure(failed)
			}

			assert.Equal(t, testCase.givenUp, giveUp)
			if testCase.givenUp {
				assert.ErrorIs(t, reported, failed)
				assert.ErrorContains(t, reported, fmt.Sprintf(
					"giving up after %d consecutive failed attempts", maxRetryAttempts))
				// Nothing is left to wake the run loop up for a failure it gave up on.
				assert.Nil(t, retries.timer)
				assert.Nil(t, retries.after)
				require.Len(t, armedDelays, maxRetryAttempts-1)
				assert.Equal(t, maxRetryDelay, armedDelays[len(armedDelays)-1])
				return
			}

			assert.Equal(t, testCase.delays, armedDelays)
			assert.ErrorIs(t, reported, failed)
			assert.ErrorContains(t, reported, fmt.Sprintf("retrying in %s (attempt %d/%d)",
				testCase.delays[len(testCase.delays)-1], testCase.failures, maxRetryAttempts))
		})
	}
}
