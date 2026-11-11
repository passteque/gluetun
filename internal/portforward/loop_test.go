package portforward

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/portforward/service"
	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

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

// expectTick makes a retry of the loop fire. The loop waits on the channel of
// a mock timer, so the send only succeeds once the loop is parked on it, and
// the retry is ordered by the test rather than by the clock.
func expectTick(t *testing.T, ticks chan<- time.Time) {
	t.Helper()
	select {
	case ticks <- time.Now():
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the loop to wait on the retry timer")
	}
}

// Test_Loop_failedPortForwardRetry checks the loop retries a port forwarding
// service which failed to start, and never restarts a working one because of
// a failure which has already been dealt with.
func Test_Loop_failedPortForwardRetry(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// retryByTimer is true when the retry is triggered by the retry timer
		// firing, and false when a new update arrives first and supersedes it.
		retryByTimer bool
		// updateRejected is true when an update the loop refuses arrives while
		// the retry timer is pending, and must leave it armed.
		updateRejected bool
	}{
		"retried_when_timer_fires": {
			retryByTimer: true,
		},
		"retried_by_update_dropping_timer": {
			retryByTimer: false,
		},
		"retried_when_timer_fires_after_a_rejected_update": {
			retryByTimer:   true,
			updateRejected: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			const vpnInterface = "tun0"
			const forwardedPort = uint16(45066)
			const retryDelay = 5 * time.Second
			gateway := netip.MustParseAddr("10.2.0.1")
			internalIP := netip.MustParseAddr("10.2.0.2")
			portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
			client := &http.Client{}

			routing := NewMockRouting(ctrl)
			routing.EXPECT().VPNLocalGatewayIP(vpnInterface).Return(gateway, nil).Times(2)
			routing.EXPECT().AssignedIP(vpnInterface, netlink.FamilyV4).Return(internalIP, nil).Times(2)
			logger := NewMockLogger(ctrl)
			portAllower := NewMockPortAllower(ctrl)
			portForwarder := NewMockPortForwarder(ctrl)
			objects := utils.PortForwardObjects{
				Logger:     logger,
				Gateway:    gateway,
				InternalIP: internalIP,
				Client:     client,
				PortsCount: 1,
			}
			// The service runs with the context of the loop, which the test
			// does not have access to
			anyContext := gomock.Any()

			// The first port forwarding fails, the second one succeeds and is
			// kept until the loop stops
			logger.EXPECT().Info("starting").Times(2)
			failed := portForwarder.EXPECT().PortForward(anyContext, objects).
				Return(nil, errors.New("TCP and UDP external ports differ: 45066 and 60808"))
			// Closed once the service is fully started a second time: the
			// keep port call happens after the port has been forwarded,
			// allowed in the firewall and written to file
			started := make(chan struct{})
			portForwarder.EXPECT().PortForward(anyContext, objects).After(failed).
				Return(map[uint16]uint16{forwardedPort: forwardedPort}, nil)
			logger.EXPECT().Info("port forwarded is 45066")
			portAllower.EXPECT().SetAllowedPort(anyContext, forwardedPort, vpnInterface).Return(nil)
			logger.EXPECT().Info("writing port file " + portFilepath)
			portForwarder.EXPECT().KeepPortForward(anyContext, objects).
				DoAndReturn(func(ctx context.Context, _ utils.PortForwardObjects) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				})
			logger.EXPECT().Info("stopping")
			portAllower.EXPECT().RemoveAllowedPort(context.Background(), forwardedPort).Return(nil)
			logger.EXPECT().Info("clearing port file " + portFilepath)

			// The retry timer belongs to the test, which decides when the retry
			// happens, so nothing sleeps and nothing depends on the machine speed.
			retryTimer := NewMocktimer(ctrl)
			ticks := make(chan time.Time)
			retryTimer.EXPECT().C().Return(ticks)
			if !testCase.retryByTimer {
				// Registered before the update below: the loop stops the
				// pending retry as it processes the update. Stopping it is what
				// prevents a second service start, remapping the port forwarded.
				retryTimer.EXPECT().Stop()
			}

			loop := NewLoop(settings.PortForwarding{
				Enabled:        new(true),
				Filepath:       &portFilepath,
				UpCommand:      new(""),
				DownCommand:    new(""),
				ListeningPorts: []uint16{0},
				PortsCount:     1,
			}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
			// The factory runs on the loop goroutine, so the delay it is called
			// with is recorded here and compared once the loop is stopped,
			// rather than asserted from a goroutine the test does not control.
			var armedDelay time.Duration
			loop.newTimer = func(duration time.Duration) timer {
				armedDelay = duration
				return retryTimer
			}
			_, err := loop.Start(t.Context())
			require.NoError(t, err)
			// Stopped even when an assertion below fails this goroutine and
			// leaves the loop running: the run context would stay alive with
			// nobody to stop it, and the test would hang until the test binary
			// times out. A second stop is a no-op.
			t.Cleanup(func() { _ = loop.Stop() })

			vpnUp := Settings{
				VPNIsUp: new(true),
				Service: service.Settings{
					PortForwarder: portForwarder,
					Interface:     vpnInterface,
				},
			}
			err = loop.UpdateWith(vpnUp)
			require.ErrorContains(t, err, "TCP and UDP external ports differ")
			assert.ErrorContains(t, err, "retrying in "+retryDelay.String())

			switch {
			case testCase.updateRejected:
				// Arrives while the retry timer is still pending, and is refused
				// by the settings validation of the loop. No service restart
				// happens, and so no timer is stopped either: no Stop call is
				// expected here, and the retry below still fires.
				portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
				rejectedUpdate := Settings{
					VPNIsUp: new(true),
					Service: service.Settings{PortsCount: 6},
				}
				err = loop.UpdateWith(rejectedUpdate)
				require.ErrorContains(t, err, "ports count too high: 6 > 5")
				expectTick(t, ticks)
			case testCase.retryByTimer:
				expectTick(t, ticks)
			default:
				// Arrives while the retry timer is still pending
				portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
				err = loop.UpdateWith(vpnUp)
				require.NoError(t, err)
			}

			expectWait(t, started, "the port forwarding service to start again")
			assert.Equal(t, []uint16{forwardedPort}, loop.GetPortsForwarded())

			// Any other service start is unexpected and fails the test, since
			// only the test can make the retry timer fire
			err = loop.Stop()
			require.NoError(t, err)
			// The only failure of the test is retried after the default delay
			assert.Equal(t, retryDelay, armedDelay)
		})
	}
}

// Test_Loop_failedPortForwardRetryBackoff checks the delay announced for the
// next retry doubles at each failure and is held at a maximum, so a server
// which will never support port forwarding does not log and call the provider
// API every few seconds for the whole tunnel session.
func Test_Loop_failedPortForwardRetryBackoff(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	const vpnInterface = "tun0"
	gateway := netip.MustParseAddr("10.2.0.1")
	internalIP := netip.MustParseAddr("10.2.0.2")
	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
	client := &http.Client{}
	errPortForward := errors.New("TCP and UDP external ports differ: 45066 and 60808")
	// The delay announced with each failed service start, one entry per attempt.
	// It doubles at each failure and is then held at 5 minutes, so 5m20s, which
	// would come after 160s, is never announced.
	retryDelays := []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
		80 * time.Second, 160 * time.Second,
		5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	}
	// Part of the error logged with the retry delay, whatever wrapped it on the
	// way from the port forwarder up to the loop
	retryError := func(retryDelay time.Duration) string {
		return errPortForward.Error() + " - retrying in " + retryDelay.String()
	}

	routing := NewMockRouting(ctrl)
	routing.EXPECT().VPNLocalGatewayIP(vpnInterface).
		Return(gateway, nil).Times(len(retryDelays))
	routing.EXPECT().AssignedIP(vpnInterface, netlink.FamilyV4).
		Return(internalIP, nil).Times(len(retryDelays))
	logger := NewMockLogger(ctrl)
	portAllower := NewMockPortAllower(ctrl)
	portForwarder := NewMockPortForwarder(ctrl)
	objects := utils.PortForwardObjects{
		Logger:     logger,
		Gateway:    gateway,
		InternalIP: internalIP,
		Client:     client,
		PortsCount: 1,
	}
	// The service runs with the context of the loop, which the test does not
	// have access to
	anyContext := gomock.Any()

	logger.EXPECT().Info("starting").Times(len(retryDelays))
	for i, retryDelay := range retryDelays {
		portForwarder.EXPECT().PortForward(anyContext, objects).
			Return(nil, errPortForward)
		if i == 0 {
			// The first failure is sent back to the update caller, which logs
			// it. The following ones are logged by the loop itself.
			continue
		}
		logger.EXPECT().Error(errorContaining{substring: retryError(retryDelay)})
	}

	retryTimer := NewMocktimer(ctrl)
	ticks := make(chan time.Time)
	retryTimer.EXPECT().C().Return(ticks).Times(len(retryDelays))

	loop := NewLoop(settings.PortForwarding{
		Enabled:        new(true),
		Filepath:       &portFilepath,
		UpCommand:      new(""),
		DownCommand:    new(""),
		ListeningPorts: []uint16{0},
		PortsCount:     1,
	}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
	// The delay the timer is armed with is not the one the loop logs, and a
	// mismatch would leave the test on the announced ladder while the loop
	// waits on another one. The loop is the only writer of the slice, and Stop
	// waits for the run goroutine to end before the test reads it back.
	var armedDelays []time.Duration
	loop.newTimer = func(delay time.Duration) timer {
		armedDelays = append(armedDelays, delay)
		return retryTimer
	}
	_, err := loop.Start(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = loop.Stop() })

	vpnUp := Settings{
		VPNIsUp: new(true),
		Service: service.Settings{
			PortForwarder: portForwarder,
			Interface:     vpnInterface,
		},
	}
	err = loop.UpdateWith(vpnUp)
	require.ErrorContains(t, err, retryError(retryDelays[0]))

	// Every attempt is driven by an event and the test never sleeps.
	for range retryDelays[1:] {
		expectTick(t, ticks)
	}

	err = loop.Stop()
	require.NoError(t, err)
	assert.Equal(t, retryDelays, armedDelays)
}

// Test_Loop_failedPortForwardRetryGivesUp checks the run ends with a fatal
// error once maxRetryAttempts failures have piled up, since only a restart of
// the program asks the provider for another VPN server, which is what a server
// refusing to forward a port for the two hours of retrying needs.
func Test_Loop_failedPortForwardRetryGivesUp(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	const vpnInterface = "tun0"
	gateway := netip.MustParseAddr("10.2.0.1")
	internalIP := netip.MustParseAddr("10.2.0.2")
	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
	client := &http.Client{}
	errPortForward := errors.New("TCP and UDP external ports differ: 45066 and 60808")
	// Delay of each attempt, doubling until the maximum, as the loop computes
	// it. The last attempt is the one giving up, so no delay is announced for
	// it and the ladder stops one entry before the attempts do.
	retryDelays := make([]time.Duration, maxRetryAttempts-1)
	retryDelay := defaultRetryDelay
	for i := range retryDelays {
		retryDelays[i] = retryDelay
		retryDelay = min(retryDelay*2, maxRetryDelay)
	}
	// Whole error logged for a failed attempt, naming the delay waited for and
	// how many attempts are left.
	attemptError := func(attempt int) string {
		return errPortForward.Error() + " - retrying in " + retryDelays[attempt-1].String() +
			fmt.Sprintf(" (attempt %d/%d)", attempt, maxRetryAttempts)
	}

	routing := NewMockRouting(ctrl)
	routing.EXPECT().VPNLocalGatewayIP(vpnInterface).Return(gateway, nil).Times(maxRetryAttempts)
	routing.EXPECT().AssignedIP(vpnInterface, netlink.FamilyV4).Return(internalIP, nil).Times(maxRetryAttempts)
	logger := NewMockLogger(ctrl)
	portAllower := NewMockPortAllower(ctrl)
	portForwarder := NewMockPortForwarder(ctrl)
	objects := utils.PortForwardObjects{
		Logger:     logger,
		Gateway:    gateway,
		InternalIP: internalIP,
		Client:     client,
		PortsCount: 1,
	}
	anyContext := gomock.Any()

	logger.EXPECT().Info("starting").Times(maxRetryAttempts)
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(nil, errPortForward).Times(maxRetryAttempts)
	// The first failure is sent back to the update caller, which logs it, and
	// the last one ends the run, so the loop logs the attempts in between.
	for attempt := 2; attempt < maxRetryAttempts; attempt++ {
		logger.EXPECT().Error(errorContaining{substring: attemptError(attempt)})
	}

	retryTimer := NewMocktimer(ctrl)
	ticks := make(chan time.Time)
	// The first maxRetryAttempts-1 failures arm a retry; the last one gives up
	// instead of waiting for another one, which no expectation covers, so a 31st
	// service start fails the test.
	retryTimer.EXPECT().C().Return(ticks).Times(maxRetryAttempts - 1)

	loop := NewLoop(settings.PortForwarding{
		Enabled:        new(true),
		Filepath:       &portFilepath,
		UpCommand:      new(""),
		DownCommand:    new(""),
		ListeningPorts: []uint16{0},
		PortsCount:     1,
	}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
	loop.newTimer = func(_ time.Duration) timer { return retryTimer }
	runError, err := loop.Start(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = loop.Stop() })

	vpnUp := Settings{
		VPNIsUp: new(true),
		Service: service.Settings{
			PortForwarder: portForwarder,
			Interface:     vpnInterface,
		},
	}
	err = loop.UpdateWith(vpnUp)
	require.ErrorContains(t, err, attemptError(1))

	// Every attempt is driven by an event and the test never sleeps, so the
	// two hours of waiting the delays announce never happen.
	for range maxRetryAttempts - 1 {
		expectTick(t, ticks)
	}

	var givenUpErr error
	select {
	case givenUpErr = <-runError:
	case <-hangContext(t).Done():
		t.Fatal("timed out waiting for the loop to give up on port forwarding")
	}
	assert.ErrorContains(t, givenUpErr,
		fmt.Sprintf("giving up after %d consecutive failed attempts", maxRetryAttempts))
	assert.ErrorIs(t, givenUpErr, errPortForward)

	err = loop.Stop()
	require.NoError(t, err)
}

// Test_Loop_failedPortForwardRetryDelayReset checks the retry delay goes back
// to its default delay once the service has started, and when an update asks
// for a new service, so a failing port forwarding of an otherwise working
// service is retried without waiting for minutes.
func Test_Loop_failedPortForwardRetryDelayReset(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	const vpnInterface = "tun0"
	const forwardedPort = uint16(45066)
	const defaultRetryDelay = 5 * time.Second
	gateway := netip.MustParseAddr("10.2.0.1")
	internalIP := netip.MustParseAddr("10.2.0.2")
	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
	client := &http.Client{}
	errPortForward := errors.New("TCP and UDP external ports differ: 45066 and 60808")
	errKeepPort := errors.New("port mapping expired")
	// Part of the error logged with the retry delay, whatever wrapped it on the
	// way from the port forwarder up to the loop
	retryError := func(retryDelay time.Duration) string {
		return errPortForward.Error() + " - retrying in " + retryDelay.String()
	}

	routing := NewMockRouting(ctrl)
	// Five service starts:
	// 1 fails, sending the default delay back to the update caller,
	// 2 fails, announcing twice the default delay,
	// 3 succeeds, which resets the delay, and its keep alive call fails,
	// 4 fails after the delay the crash took, announcing twice the default
	// delay rather than the 20s the backoff had reached before the success,
	// 5 fails, announced with the default delay as well, since a new update
	// reset the delay before it and sent the retry of the attempt 4 back.
	const attempts = 5
	routing.EXPECT().VPNLocalGatewayIP(vpnInterface).Return(gateway, nil).Times(attempts)
	routing.EXPECT().AssignedIP(vpnInterface, netlink.FamilyV4).Return(internalIP, nil).Times(attempts)
	logger := NewMockLogger(ctrl)
	portAllower := NewMockPortAllower(ctrl)
	portForwarder := NewMockPortForwarder(ctrl)
	objects := utils.PortForwardObjects{
		Logger:     logger,
		Gateway:    gateway,
		InternalIP: internalIP,
		Client:     client,
		PortsCount: 1,
	}
	anyContext := gomock.Any()

	logger.EXPECT().Info("starting").Times(attempts)
	// One expectation per attempt, in the order they run: gomock consumes the
	// expectations of identical arguments in declaration order.
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(nil, errPortForward)
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(nil, errPortForward)
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(map[uint16]uint16{forwardedPort: forwardedPort}, nil)
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(nil, errPortForward)
	portForwarder.EXPECT().PortForward(anyContext, objects).
		Return(nil, errPortForward)

	logger.EXPECT().Error(errorContaining{substring: retryError(2 * defaultRetryDelay)})
	// Logged by the loop when it receives the keep alive failure of the attempt
	// 3, and waited for before driving the retry it schedules, so the crash is
	// not mistaken for the attempt 4 and their order is not left to the
	// scheduler.
	crashLogged := make(chan struct{})
	logger.EXPECT().Error(errorContaining{substring: errKeepPort.Error() +
		" - retrying in " + defaultRetryDelay.String()}).
		DoAndReturn(func(_ string) {
			close(crashLogged)
		})
	// The crash of the attempt 3 has taken the default delay slot, so the
	// attempt 4 announces twice the default delay.
	logger.EXPECT().Error(errorContaining{substring: retryError(2 * defaultRetryDelay)})

	// What the successful attempt 3 does, and cleans up after when the keep
	// alive call fails
	logger.EXPECT().Info("port forwarded is 45066")
	portAllower.EXPECT().SetAllowedPort(anyContext, forwardedPort, vpnInterface).Return(nil)
	logger.EXPECT().Info("writing port file " + portFilepath)
	portForwarder.EXPECT().KeepPortForward(anyContext, objects).
		Return(errKeepPort)
	portAllower.EXPECT().RemoveAllowedPort(context.Background(), forwardedPort).Return(nil)
	logger.EXPECT().Info("clearing port file " + portFilepath)

	retryTimer := NewMocktimer(ctrl)
	ticks := make(chan time.Time)
	// Armed by the attempts 1, 2, 4 and 5, and by the crash of the attempt 3,
	// which succeeded and so reset the delay back to its default.
	retryTimer.EXPECT().C().Return(ticks).Times(5)
	// Registered before the update below: the update supersedes the retry
	// pending from the attempt 4, which is why its timer is stopped.
	retryTimer.EXPECT().Stop()

	loop := NewLoop(settings.PortForwarding{
		Enabled:        new(true),
		Filepath:       &portFilepath,
		UpCommand:      new(""),
		DownCommand:    new(""),
		ListeningPorts: []uint16{0},
		PortsCount:     1,
	}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
	loop.newTimer = func(_ time.Duration) timer { return retryTimer }
	_, err := loop.Start(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = loop.Stop() })

	vpnUp := Settings{
		VPNIsUp: new(true),
		Service: service.Settings{
			PortForwarder: portForwarder,
			Interface:     vpnInterface,
		},
	}
	err = loop.UpdateWith(vpnUp)
	require.ErrorContains(t, err, retryError(defaultRetryDelay))

	// Attempts 2 and 3, the later one succeeding
	for range 2 {
		expectTick(t, ticks)
	}

	// The crash of the attempt 3 schedules the retry driving the attempt 4,
	// instead of restarting the service right away.
	expectWait(t, crashLogged, "the keep alive failure to be logged")
	expectTick(t, ticks)

	// The update arrives while the retry of the attempt 4 is pending, and the
	// error of the attempt 5 it triggers is sent back to the caller: it announces
	// the default delay, and not the 20s the backoff had reached
	portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
	err = loop.UpdateWith(vpnUp)
	require.ErrorContains(t, err, retryError(defaultRetryDelay))

	err = loop.Stop()
	require.NoError(t, err)
}

// Test_Loop_SetPortsForwarded checks the ports of the running service are
// replaced, and that the call says there is nothing to replace the ports on
// while no service runs, which the HTTP handler answers with a status telling
// the client to try again later.
func Test_Loop_SetPortsForwarded(t *testing.T) {
	t.Parallel()

	const forwardedPort = uint16(45066)

	t.Run("no_service_running", func(t *testing.T) {
		t.Parallel()

		loop := &Loop{}

		err := loop.SetPortsForwarded([]uint16{forwardedPort})

		assert.ErrorIs(t, err, ErrServiceNotRunning)
	})

	t.Run("service_running", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		runCtx := t.Context()
		runningService := NewMockService(ctrl)
		runningService.EXPECT().SetPortsForwarded(runCtx, []uint16{forwardedPort}).Return(nil)

		loop := &Loop{}
		loop.runCtx = runCtx
		loop.setService(runningService)

		err := loop.SetPortsForwarded([]uint16{forwardedPort})

		require.NoError(t, err)
	})
}
