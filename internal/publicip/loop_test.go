package publicip

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/publicip/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTest = errors.New("test error")

// failingThenSucceedingFetcher implements [api.Fetcher] and fails
// the first `failures` calls to FetchInfo, then succeeds.
type failingThenSucceedingFetcher struct {
	failures uint32
	calls    atomic.Uint32
	result   models.PublicIP
}

func (f *failingThenSucceedingFetcher) String() string      { return "test" }
func (f *failingThenSucceedingFetcher) CanFetchAnyIP() bool { return true }
func (f *failingThenSucceedingFetcher) Token() string       { return "" }

func (f *failingThenSucceedingFetcher) FetchInfo(_ context.Context, _ netip.Addr) (
	result models.PublicIP, err error,
) {
	call := f.calls.Add(1)
	if call <= f.failures {
		return models.PublicIP{}, errTest
	}
	return f.result, nil
}

type testLogger struct{}

func (l *testLogger) Info(string)  {}
func (l *testLogger) Warn(string)  {}
func (l *testLogger) Error(string) {}

func newTestLoop(fetcher api.Fetcher, initialBackoff time.Duration,
	ipFilepath string,
) *Loop {
	logger := &testLogger{}
	enabled := true
	return &Loop{
		settings: settings.PublicIP{
			Enabled:    &enabled,
			IPFilepath: &ipFilepath,
		},
		fetcher:             api.NewResilient([]api.Fetcher{fetcher}, logger),
		logger:              logger,
		puid:                os.Getuid(),
		pgid:                os.Getgid(),
		retryInitialBackoff: initialBackoff,
		retryMaxBackoff:     20 * initialBackoff,
		timeNow:             time.Now,
	}
}

func Test_Loop_retries_after_failed_fetch(t *testing.T) {
	t.Parallel()

	fetcher := &failingThenSucceedingFetcher{
		failures: 2,
		result: models.PublicIP{
			IP:      netip.AddrFrom4([4]byte{1, 2, 3, 4}),
			Country: "Country",
			Region:  "Region",
			City:    "City",
		},
	}
	const initialBackoff = 5 * time.Millisecond
	ipFilepath := filepath.Join(t.TempDir(), "ip")
	loop := newTestLoop(fetcher, initialBackoff, ipFilepath)

	_, err := loop.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		err := loop.Stop()
		assert.NoError(t, err)
	})

	// The tunnel up trigger fetch fails and schedules a retry.
	err = loop.RunOnce(context.Background())
	require.ErrorIs(t, err, errTest)

	// The first retry fails and the second retry succeeds.
	const maxWait = 10 * time.Second
	deadline := time.Now().Add(maxWait)
	for !loop.GetData().IP.IsValid() && time.Now().Before(deadline) {
		time.Sleep(initialBackoff)
	}

	assert.Equal(t, fetcher.result, loop.GetData())
	assert.Equal(t, uint32(3), fetcher.calls.Load())
	content, err := os.ReadFile(ipFilepath)
	require.NoError(t, err)
	assert.Equal(t, fetcher.result.IP.String(), string(content))
}

func Test_Loop_ClearData_stops_retries(t *testing.T) {
	t.Parallel()

	fetcher := &failingThenSucceedingFetcher{
		failures: 1000, // always fail
	}
	const initialBackoff = 100 * time.Millisecond
	ipFilepath := filepath.Join(t.TempDir(), "ip")
	loop := newTestLoop(fetcher, initialBackoff, ipFilepath)

	_, err := loop.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		err := loop.Stop()
		assert.NoError(t, err)
	})

	// The tunnel up trigger fetch fails and schedules a retry.
	err = loop.RunOnce(context.Background())
	require.ErrorIs(t, err, errTest)

	// The VPN tunnel goes down before the first retry runs.
	err = loop.ClearData()
	require.NoError(t, err)

	// Wait enough time for multiple retries to have run.
	time.Sleep(5 * initialBackoff)
	assert.Equal(t, uint32(1), fetcher.calls.Load())
}
