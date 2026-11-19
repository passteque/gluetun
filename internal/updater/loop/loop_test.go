package loop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// hangContext returns a context canceled shortly before the test binary
// timeout, so a loop wedged by a bug fails with a clear message instead of a
// package-wide timeout panic. No assertion depends on its value or on machine
// speed: each step of a test waits for the next event to actually happen.
func hangContext(t *testing.T) context.Context {
	t.Helper()
	if deadline, ok := t.Deadline(); ok {
		// Time out 10% before the test binary does
		ctx, cancel := context.WithDeadline(t.Context(), deadline.Add(-time.Until(deadline)/10))
		t.Cleanup(cancel)
		return ctx
	}
	// The test binary runs with no timeout, so guard a wedged loop with a
	// fixed duration, still canceled along with the test itself
	const guardTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), guardTimeout)
	t.Cleanup(cancel)
	return ctx
}

// heldUpdate returns an UpdateServers behavior which never does any work: it
// reports the update as started to the test, then waits for the test to hand
// over the result to return, or for the loop to cancel the update. This is
// what keeps the tests event driven instead of time driven.
func heldUpdate(started, canceled chan<- struct{}, results <-chan error) func(
	ctx context.Context, providers []string, minRatio float64) error {
	return func(ctx context.Context, _ []string, _ float64) error {
		select {
		case started <- struct{}{}:
		case <-ctx.Done():
			signal(canceled)
			return ctx.Err()
		}
		select {
		case err := <-results:
			return err
		case <-ctx.Done():
			signal(canceled)
			return ctx.Err()
		}
	}
}

// signal sends without ever blocking, only informing a test waiting for it.
func signal(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// newUpdateSignals creates the signals shared with heldUpdate. They are
// buffered so an update never blocks forever on a test which moved on.
func newUpdateSignals() (started, canceled chan struct{}, results chan error) {
	return make(chan struct{}, 64), make(chan struct{}, 64), make(chan error)
}

// expectSignal waits for a signal coming from the loop, failing the test if it
// does not arrive, which is how a wedged loop shows up.
func expectSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-hangContext(t).Done():
		t.Fatalf("timed out waiting for %s", description)
	}
}

// giveUpdateResult hands over the result of the update in progress. The test
// must know an update is in progress and will not be canceled meanwhile.
func giveUpdateResult(t *testing.T, results chan<- error, err error) {
	t.Helper()
	select {
	case results <- err:
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the update in progress to pick up its result")
	}
}

// expectTick delivers a tick to the restarting ticker, failing the test if it
// does not listen for it.
func expectTick(t *testing.T, ticks chan<- time.Time) {
	t.Helper()
	select {
	case ticks <- time.Now():
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the restarting ticker to listen for a tick")
	}
}

// expectStartRequest asks the loop to start an update now, the same way the
// restarting ticker does, and fails the test if the loop does not acknowledge
// the request.
func expectStartRequest(ctx context.Context, t *testing.T, testLoop *Loop) {
	t.Helper()
	returnedCh := make(chan bool)
	go func() {
		returnedCh <- testLoop.atomicStart(ctx)
	}()
	select {
	case started := <-returnedCh:
		assert.True(t, started, "start request reported the loop as not started")
	case <-hangContext(t).Done():
		t.Fatal("start request did not return: the loop is wedged")
	}
}

// setStatus changes the loop status, failing the test if the loop does not
// carry the transition out.
func setStatus(ctx context.Context, t *testing.T, testLoop *Loop,
	status models.LoopStatus,
) (outcome string) {
	t.Helper()
	type result struct {
		outcome string
		err     error
	}
	returnedCh := make(chan result)
	go func() {
		outcome, err := testLoop.SetStatus(ctx, status)
		returnedCh <- result{outcome: outcome, err: err}
	}()
	select {
	case result := <-returnedCh:
		assert.NoError(t, result.err)
		return result.outcome
	case <-hangContext(t).Done():
		t.Fatal("SetStatus did not return: the loop is wedged")
		return ""
	}
}

func Test_Loop_Run_UpdatePerStartRequest(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results)).Times(2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	expectStartRequest(ctx, t, testLoop)
	expectSignal(t, started, "the first update to start")
	giveUpdateResult(t, results, nil)

	// The loop accepts a new start request once the previous update ended,
	// interrupting nothing since no update is running
	mockLogger.EXPECT().Info("starting")
	expectStartRequest(ctx, t, testLoop)
	expectSignal(t, started, "the second update to start")
	giveUpdateResult(t, results, nil)

	cancel()
	<-runDone
}

// Regression test: the crashed flag was never reset, so a start request
// following a failed update was never acknowledged, wedging the loop.
func Test_Loop_Run_StartRequestAfterCrash(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results)).Times(3)
	mockLogger.EXPECT().Error("fake update error")
	mockLogger.EXPECT().Info("retrying in 1ms")
	mockLogger.EXPECT().Info("starting")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:       state{status: constants.Stopped},
		updater:     mockUpdater,
		logger:      mockLogger,
		start:       make(chan struct{}),
		running:     make(chan models.LoopStatus),
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
		backoffTime: time.Millisecond,
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	expectStartRequest(ctx, t, testLoop)
	expectSignal(t, started, "the first update to start")
	giveUpdateResult(t, results, errors.New("fake update error"))

	// The loop retries the update on its own after a failure
	expectSignal(t, started, "the failed update to be retried")
	giveUpdateResult(t, results, nil)

	// The retry must not have consumed the acknowledgement owed to the next
	// start request coming from a caller
	expectStartRequest(ctx, t, testLoop)
	expectSignal(t, started, "the third update to start")
	giveUpdateResult(t, results, nil)

	cancel()
	<-runDone
}

func Test_Loop_SetStatus_RunningFromStopped(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	outcome := setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "running", outcome)
	// The update is held by the test, so the status cannot have moved on
	assert.Equal(t, constants.Running, testLoop.GetStatus())

	expectSignal(t, started, "the update to start")
	giveUpdateResult(t, results, nil)

	cancel()
	<-runDone
}

func Test_Loop_SetStatus_AlreadyRunning(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	outcome := setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "running", outcome)
	expectSignal(t, started, "the update to start")

	outcome = setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "already running", outcome)

	giveUpdateResult(t, results, nil)

	cancel()
	<-runDone
}

func Test_Loop_SetStatus_StoppedThenRunning(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results)).Times(2)
	mockLogger.EXPECT().Info("stopping")
	mockLogger.EXPECT().Info("starting")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	outcome := setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "running", outcome)
	expectSignal(t, started, "the first update to start")

	outcome = setStatus(ctx, t, testLoop, constants.Stopped)
	assert.Equal(t, "stopped", outcome)
	expectSignal(t, canceled, "the update to be canceled")
	assert.Equal(t, constants.Stopped, testLoop.GetStatus())

	// The loop can be started again after being stopped
	outcome = setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "running", outcome)
	expectSignal(t, started, "the second update to start")

	giveUpdateResult(t, results, nil)

	cancel()
	<-runDone
}

// A caller giving up (e.g. a client timeout) while the loop is stopping the
// update does not leave the status stuck at stopping either.
func Test_Loop_SetStatus_StoppedCallerCanceled(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results))
	mockLogger.EXPECT().Info("stopping")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)

	outcome := setStatus(ctx, t, testLoop, constants.Running)
	assert.Equal(t, "running", outcome)
	expectSignal(t, started, "the update to start")

	stopCtx, stopCancel := context.WithCancel(ctx)
	defer stopCancel()
	outcomeCh := make(chan string)
	go func() {
		outcome, err := testLoop.SetStatus(stopCtx, constants.Stopped)
		assert.NoError(t, err)
		outcomeCh <- outcome
	}()

	// The update being canceled means the loop received the stop request, so
	// the caller is now waiting for the stopped notification
	expectSignal(t, canceled, "the update to be canceled")
	stopCancel()

	select {
	case outcome := <-outcomeCh:
		assert.Equal(t, "stopped", outcome)
	case <-hangContext(t).Done():
		t.Fatal("stopped transition did not complete: the loop is wedged")
	}
	assert.Equal(t, constants.Stopped, testLoop.GetStatus())

	cancel()
	<-runDone
}

// A context canceled before the request reaches the loop must not block, and
// must restore the previous status.
func Test_Loop_SetStatus_ContextCanceledBeforeRequest(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	testLoop := &Loop{
		state:   state{status: constants.Stopped},
		updater: mockUpdater,
		logger:  mockLogger,
		start:   make(chan struct{}),
		running: make(chan models.LoopStatus),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	outcome := setStatus(canceledCtx, t, testLoop, constants.Running)
	assert.Equal(t, "stopped", outcome)
	assert.Equal(t, constants.Stopped, testLoop.GetStatus())

	outcome = setStatus(canceledCtx, t, testLoop, constants.Stopped)
	assert.Equal(t, "already stopped", outcome)
}

// Regression test: the ticker blocked on sending the running notification, so
// it stopped requesting updates after the first one.
func Test_Loop_RunRestartTicker_KeepsUpdating(t *testing.T) {
	t.Parallel()
	period := time.Hour
	ctrl := gomock.NewController(t)
	mockUpdater := NewMockUpdater(ctrl)
	mockLogger := NewMockLogger(ctrl)
	mockTimer := NewMocktimer(ctrl)
	started, canceled, results := newUpdateSignals()
	mockUpdater.EXPECT().
		UpdateServers(liveContext{}, gomock.Nil(), 0.0).
		DoAndReturn(heldUpdate(started, canceled, results)).Times(3)
	// The first tick reaches the loop before it runs, the two others while it
	// is running an update
	mockLogger.EXPECT().Info("starting").Times(2)

	ticksCh := make(chan time.Time)
	mockTimer.EXPECT().C().Return(ticksCh).Times(4)
	// Armed once with the period and re-armed after each of the 3 ticks. Every
	// arm is reported, so the test can await the last one instead of canceling
	// the ticker while it is between a tick and arming itself for the next one
	armsCh := make(chan struct{}, 4)
	mockTimer.EXPECT().Reset(period).
		Do(func(time.Duration) { signal(armsCh) }).Times(4)
	// Stopped on creation and when the context is done
	mockTimer.EXPECT().Stop().Times(2)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	testLoop := &Loop{
		state: state{
			status:   constants.Stopped,
			settings: settings.Updater{Period: &period},
		},
		updater:   mockUpdater,
		logger:    mockLogger,
		start:     make(chan struct{}),
		running:   make(chan models.LoopStatus),
		stop:      make(chan struct{}),
		stopped:   make(chan struct{}),
		timeNow:   time.Now,
		timeSince: time.Since,
		newTimer:  func() timer { return mockTimer },
	}
	runDone := make(chan struct{})
	go testLoop.Run(ctx, runDone)
	tickerDone := make(chan struct{})
	go testLoop.RunRestartTicker(ctx, tickerDone)

	// Consumed first so the arm signals below stay in lockstep with the ticks
	expectSignal(t, armsCh, "the ticker to arm itself with the period")
	for range 3 {
		expectTick(t, ticksCh)
		expectSignal(t, started, "an update to start")
		expectSignal(t, armsCh, "the ticker to arm itself for the next tick")
	}

	cancel()
	<-runDone
	<-tickerDone
}
