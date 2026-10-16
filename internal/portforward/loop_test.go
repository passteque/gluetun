package portforward

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_nextRetryDelay(t *testing.T) {
	t.Parallel()

	delays := []time.Duration{minRetryDelay}
	for range 5 {
		delays = append(delays, nextRetryDelay(delays[len(delays)-1]))
	}

	expected := []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second,
		40 * time.Second, time.Minute, time.Minute,
	}
	assert.Equal(t, expected, delays)
}
