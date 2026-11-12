package backoff

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_State_Failure(t *testing.T) {
	t.Parallel()

	const (
		short        = 5 * time.Second
		medium       = 10 * time.Second
		long         = 20 * time.Second
		hold         = 40 * time.Second
		minute       = time.Minute
		twoMinutes   = 2 * time.Minute
		fiveAttempts = 3
	)

	testCases := map[string]struct {
		initial     time.Duration
		maximum     time.Duration
		maxFailures int
		// failures is how many of them are booked one after the other.
		failures int
		// want is what each booked failure is worth, in the order they are booked.
		want []Failure
	}{
		"one_failure_is_worth_the_initial_delay": {
			initial:     short,
			maximum:     hold,
			maxFailures: 0,
			failures:    1,
			want: []Failure{{
				Delay: short, Attempts: 1, Max: 0, GiveUp: false,
			}},
		},
		"the_delay_doubles_and_is_held_at_the_maximum": {
			initial:     short,
			maximum:     hold,
			maxFailures: 0,
			failures:    4,
			want: []Failure{
				{Delay: short, Attempts: 1, Max: 0, GiveUp: false},
				{Delay: medium, Attempts: 2, Max: 0, GiveUp: false},
				{Delay: long, Attempts: 3, Max: 0, GiveUp: false},
				{Delay: hold, Attempts: 4, Max: 0, GiveUp: false},
			},
		},
		"a_maximum_below_the_initial_delay_is_held_at_the_initial_delay": {
			initial:     minute,
			maximum:     short,
			maxFailures: 0,
			failures:    3,
			want: []Failure{
				{Delay: minute, Attempts: 1, Max: 0, GiveUp: false},
				{Delay: minute, Attempts: 2, Max: 0, GiveUp: false},
				{Delay: minute, Attempts: 3, Max: 0, GiveUp: false},
			},
		},
		"no_maximum_of_failures_is_a_backoff_which_never_ends": {
			initial:     short,
			maximum:     twoMinutes,
			maxFailures: 0,
			failures:    6,
			want: []Failure{
				{Delay: short, Attempts: 1, Max: 0, GiveUp: false},
				{Delay: medium, Attempts: 2, Max: 0, GiveUp: false},
				{Delay: long, Attempts: 3, Max: 0, GiveUp: false},
				{Delay: 40 * time.Second, Attempts: 4, Max: 0, GiveUp: false},
				{Delay: 80 * time.Second, Attempts: 5, Max: 0, GiveUp: false},
				{Delay: twoMinutes, Attempts: 6, Max: 0, GiveUp: false},
			},
		},
		"give_up_once_the_maximum_of_failures_is_reached": {
			initial:     short,
			maximum:     minute,
			maxFailures: fiveAttempts,
			failures:    fiveAttempts,
			want: []Failure{
				{Delay: short, Attempts: 1, Max: fiveAttempts, GiveUp: false},
				{Delay: medium, Attempts: 2, Max: fiveAttempts, GiveUp: false},
				{Delay: long, Attempts: 3, Max: fiveAttempts, GiveUp: true},
			},
		},
		"give_up_stays_once_reached": {
			initial:     short,
			maximum:     minute,
			maxFailures: fiveAttempts,
			failures:    fiveAttempts + 1,
			want: []Failure{
				{Delay: short, Attempts: 1, Max: fiveAttempts, GiveUp: false},
				{Delay: medium, Attempts: 2, Max: fiveAttempts, GiveUp: false},
				{Delay: long, Attempts: 3, Max: fiveAttempts, GiveUp: true},
				{Delay: 40 * time.Second, Attempts: 4, Max: fiveAttempts, GiveUp: true},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			state := New(testCase.initial, testCase.maximum, testCase.maxFailures)

			for i, want := range testCase.want {
				failure := state.Failure()
				assert.Equal(t, want, failure, "failure %d", i+1)
			}
		})
	}
}

func Test_State_Reset(t *testing.T) {
	t.Parallel()

	const (
		initial = 5 * time.Second
		medium  = 10 * time.Second
		hold    = 40 * time.Second
	)

	state := New(initial, hold, 10)
	assert.Equal(t, initial, state.Failure().Delay)
	assert.Equal(t, medium, state.Failure().Delay)

	state.Reset()

	// Both the delay and the count of consecutive failures start over, so a
	// failure is worth the initial delay again and is the first one again.
	failure := state.Failure()
	assert.Equal(t, Failure{Delay: initial, Attempts: 1, Max: 10}, failure)
}
