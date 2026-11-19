package publicip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	"go.uber.org/mock/gomock"
)

var errTest = errors.New("network down")

// hangContext returns a context canceled shortly after a wait started, so a
// loop wedged by a bug fails with a clear message instead of hanging the whole
// package until the go test timeout.
func hangContext(t *testing.T) context.Context {
	t.Helper()
	const hangTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), hangTimeout)
	t.Cleanup(cancel)
	return ctx
}

func expectWait(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-hangContext(t).Done():
		t.Fatalf("timed out waiting for %s", description)
	}
}

// expectTick makes an attempt of the loop happen. The loop waits on the channel
// of a mock timer, so the send only succeeds once the loop is parked on it, and
// the retry is ordered by the test rather than by the clock.
func expectTick(t *testing.T, ticks chan<- time.Time) {
	t.Helper()
	select {
	case ticks <- time.Now():
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the loop to wait on the retry timer")
	}
}

// expectFetch waits for the fake fetcher to have been called. Its channel is
// buffered, so a call is never lost, and the test reads them in order.
func expectFetch(t *testing.T, arrived <-chan struct{}) {
	t.Helper()
	select {
	case <-arrived:
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the fetcher to be called")
	}
}

// fakeFetcher implements [api.Fetcher] and fails as many times as the errors it
// is given, each of them nil being a success, the last one being kept once the
// list is over.
type fakeFetcher struct {
	errs    []error
	address models.PublicIP
	calls   atomic.Uint32
	arrived chan struct{}
}

func (f *fakeFetcher) String() string      { return "fake" }
func (f *fakeFetcher) CanFetchAnyIP() bool { return true }
func (f *fakeFetcher) Token() string       { return "" }

func (f *fakeFetcher) FetchInfo(ctx context.Context, _ netip.Addr) (
	result models.PublicIP, err error,
) {
	call := int(f.calls.Add(1))
	if call > len(f.errs) {
		call = len(f.errs)
	}
	select {
	case f.arrived <- struct{}{}:
	case <-ctx.Done():
		return models.PublicIP{}, ctx.Err()
	}
	return f.address, f.errs[call-1]
}

// loopFixture gathers a loop with a single fake fetcher, the retry timer the
// test owns, and the delays the loop armed its attempts with.
type loopFixture struct {
	loop       *Loop
	logger     *MockLogger
	retryTimer *Mocktimer
	ticks      chan time.Time
	fetcher    *fakeFetcher
	address    models.PublicIP
	filepath   string
	// armedDelays is written by the loop goroutine, and read by the test only
	// once the loop is stopped.
	armedDelays []time.Duration
}

// newLoopFixture starts a loop with a fake fetcher answering the errors given,
// and a retry timer the test fires by hand, so nothing sleeps and nothing
// depends on the speed of the machine.
func newLoopFixture(t *testing.T, enabled bool, errs ...error) *loopFixture {
	t.Helper()

	address := models.PublicIP{
		IP:      netip.MustParseAddr("1.2.3.4"),
		Country: "FR",
		Region:  "IDF",
		City:    "Paris",
	}
	ipFilepath := filepath.Join(t.TempDir(), "ip")
	fetcher := &fakeFetcher{
		errs:    errs,
		address: address,
		arrived: make(chan struct{}, 8),
	}

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)

	loop, err := NewLoop(settings.PublicIP{
		Enabled:    &enabled,
		IPFilepath: &ipFilepath,
	}, os.Getuid(), os.Getgid(), &http.Client{}, logger)
	require.NoError(t, err)
	loop.fetcher.UpdateFetchers([]api.Fetcher{fetcher})

	fixture := &loopFixture{
		loop:       loop,
		logger:     logger,
		retryTimer: NewMocktimer(ctrl),
		ticks:      make(chan time.Time),
		fetcher:    fetcher,
		address:    address,
		filepath:   ipFilepath,
	}
	// The factory runs on the loop goroutine, so the delay it is called with is
	// recorded here and compared once the loop is stopped, rather than asserted
	// from a goroutine the test does not control.
	loop.newTimer = func(duration time.Duration) timer {
		fixture.armedDelays = append(fixture.armedDelays, duration)
		return fixture.retryTimer
	}

	_, err = loop.Start(t.Context())
	require.NoError(t, err)
	// Stopped even when an assertion below fails this goroutine and leaves the
	// loop running: the run context would stay alive with nobody to stop it, and
	// the test would hang until the test binary times out. A second stop is a
	// no-op.
	t.Cleanup(func() { _ = loop.Stop() })

	return fixture
}

// failureMessage is the error a failed fetch answers with, the delay of the
// attempt the loop booked being part of it, so whoever reads it knows the
// failure is not the end of the story.
func failureMessage(delay time.Duration, attempt uint) string {
	return fmt.Sprintf("fetching information: all fetchers failed: fake: network down"+
		" - retrying in %s (attempt %d)", delay, attempt)
}

// successMessage is the log line a fetch answering the public IP address is
// followed by.
func (f *loopFixture) successMessage() string {
	return "Public IP address is " + f.address.IP.String() +
		" (" + f.address.Country + ", " + f.address.Region + ", " + f.address.City +
		" - source: fake)"
}

// Test_Loop_RunOnce_retry checks a fetch which failed is retried by the loop on
// its own, the delay of each attempt doubling up to a maximum and starting over
// once a fetch has gone through, and the public IP address being stored and
// written once one of the attempts succeeds.
func Test_Loop_RunOnce_retry(t *testing.T) {
	t.Parallel()

	const firstDelay = 10 * time.Second
	const secondDelay = 20 * time.Second

	fixture := newLoopFixture(t, true, errTest, errTest, nil, errTest, nil)
	// Three attempts are booked, and only the first failure has someone to
	// report to, the caller of RunOnce: the failure of an attempt of the loop
	// itself is logged by the loop.
	fixture.retryTimer.EXPECT().C().Return(fixture.ticks).Times(3)
	fixture.retryTimer.EXPECT().Stop()
	fixture.logger.EXPECT().Info(fixture.successMessage()).Times(2)
	fixture.logger.EXPECT().Error(failureMessage(secondDelay, 2))

	err := fixture.loop.RunOnce(t.Context())
	require.ErrorContains(t, err, failureMessage(firstDelay, 1))
	expectFetch(t, fixture.fetcher.arrived)

	// The attempt the loop booked for itself, which fails and books a longer
	// delay.
	expectTick(t, fixture.ticks)
	expectFetch(t, fixture.fetcher.arrived)
	// Back to the loop select, so the attempt above is over and the delay of the
	// one booked below has been recorded.
	require.NoError(t, fixture.loop.UpdateWith(settings.PublicIP{}))

	// The last attempt of the loop, which goes through this time.
	expectTick(t, fixture.ticks)
	expectFetch(t, fixture.fetcher.arrived)
	require.NoError(t, fixture.loop.UpdateWith(settings.PublicIP{}))
	assert.Equal(t, fixture.address, fixture.loop.GetData())
	contents, err := os.ReadFile(fixture.filepath)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", string(contents))

	// A fresh tunnel up is a fresh chance, so the delays start over rather than
	// carry on from the 20s the outage above worked up to.
	err = fixture.loop.RunOnce(t.Context())
	require.ErrorContains(t, err, failureMessage(firstDelay, 1))
	expectFetch(t, fixture.fetcher.arrived)

	err = fixture.loop.RunOnce(t.Context())
	require.NoError(t, err)
	expectFetch(t, fixture.fetcher.arrived)

	require.NoError(t, fixture.loop.Stop())
	assert.Equal(t, []time.Duration{firstDelay, secondDelay, firstDelay},
		fixture.armedDelays)
}

// Test_Loop_RunOnce_supersedesRetry checks a tunnel coming up while an attempt
// is pending: the fetch of the new connection happens right away, and drops the
// attempt booked for the failure before it, so the information is never fetched
// twice for the same failure.
func Test_Loop_RunOnce_supersedesRetry(t *testing.T) {
	t.Parallel()

	const firstDelay = 10 * time.Second

	fixture := newLoopFixture(t, true, errTest, nil)
	stopped := make(chan struct{})
	fixture.retryTimer.EXPECT().C().Return(fixture.ticks)
	// Stopping the attempt pending is what the test waits on below, so the drop
	// is ordered by the loop rather than by the clock.
	fixture.retryTimer.EXPECT().Stop().DoAndReturn(func() { close(stopped) })
	fixture.logger.EXPECT().Info(fixture.successMessage())

	err := fixture.loop.RunOnce(t.Context())
	require.ErrorContains(t, err, failureMessage(firstDelay, 1))
	expectFetch(t, fixture.fetcher.arrived)

	// The tunnel came up again, before the attempt pending fired.
	err = fixture.loop.RunOnce(t.Context())
	require.NoError(t, err)
	expectFetch(t, fixture.fetcher.arrived)
	expectWait(t, stopped, "the attempt pending to be dropped by the new tunnel up")

	require.NoError(t, fixture.loop.UpdateWith(settings.PublicIP{}))
	assert.Equal(t, uint32(2), fixture.fetcher.calls.Load())
	assert.Equal(t, fixture.address, fixture.loop.GetData())

	require.NoError(t, fixture.loop.Stop())
	assert.Equal(t, []time.Duration{firstDelay}, fixture.armedDelays)
}

// Test_Loop_ClearData_stopsRetry checks the VPN connection going down drops the
// attempt pending: fetching with no connection answers nothing but timeouts, and
// the tunnel up which follows triggers a fetch of its own.
func Test_Loop_ClearData_stopsRetry(t *testing.T) {
	t.Parallel()

	const firstDelay = 10 * time.Second

	fixture := newLoopFixture(t, true, errTest)
	stopped := make(chan struct{})
	fixture.retryTimer.EXPECT().C().Return(fixture.ticks)
	// Stopping the attempt pending is what the test waits on, so nothing about
	// the connection going down depends on the clock.
	fixture.retryTimer.EXPECT().Stop().DoAndReturn(func() { close(stopped) })

	err := fixture.loop.RunOnce(t.Context())
	require.ErrorContains(t, err, failureMessage(firstDelay, 1))
	expectFetch(t, fixture.fetcher.arrived)

	// Cleared from a goroutine of its own: the send asking the loop to drop the
	// attempt waits for the loop to be back in its select, so a signal lost is
	// reported by the timeout below rather than by the test hanging there. The
	// goroutine stays parked when the test fails, which is harmless since the
	// test binary exits with it.
	cleared := make(chan error)
	go func() { cleared <- fixture.loop.ClearData() }()
	expectWait(t, stopped, "the attempt pending to be dropped")
	require.NoError(t, <-cleared)

	// Back through the loop select, so the connection going down is all the loop
	// made of the failure: the timeout of a second fetch would tell the same
	// story, the tunnel being down.
	require.NoError(t, fixture.loop.UpdateWith(settings.PublicIP{}))
	assert.Equal(t, uint32(1), fixture.fetcher.calls.Load())
	assert.Equal(t, models.PublicIP{}, fixture.loop.GetData())

	// Nothing left armed, so stopping the loop has no attempt to drop.
	require.NoError(t, fixture.loop.Stop())
	assert.Equal(t, []time.Duration{firstDelay}, fixture.armedDelays)
}

// Test_Loop_RunOnce_disabled checks a loop asked to not fetch the public IP
// address answers nobody can fetch it, and books no attempt to.
func Test_Loop_RunOnce_disabled(t *testing.T) {
	t.Parallel()

	fixture := newLoopFixture(t, false, errTest)
	// No call to the retry timer is expected, and one happening is what fails
	// the test.

	err := fixture.loop.RunOnce(t.Context())
	require.NoError(t, err)
	assert.Equal(t, uint32(0), fixture.fetcher.calls.Load())

	require.NoError(t, fixture.loop.Stop())
	assert.Empty(t, fixture.armedDelays)
}
