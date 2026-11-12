package portforward

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
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

// fakeClock is a clock the test advances by hand, so the uptime of a service
// reaching minutes is simulated without waiting for them. The loop reads it on
// its own goroutine while the test advances it from a mock call running on the
// service goroutine, hence the mutex.
type fakeClock struct {
	nowMutex sync.Mutex
	now      time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now()}
}

func (c *fakeClock) Now() (now time.Time) {
	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()
	return c.now
}

func (c *fakeClock) Advance(by time.Duration) {
	c.nowMutex.Lock()
	defer c.nowMutex.Unlock()
	c.now = c.now.Add(by)
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
		// vpnDownWhilePending is true when the VPN goes down while the retry
		// timer is pending, which supersedes the retry and leaves the loop with
		// a service disabled for as long as the tunnel is down.
		vpnDownWhilePending bool
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
		"retried_by_update_following_the_vpn_going_down": {
			vpnDownWhilePending: true,
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
			case testCase.vpnDownWhilePending:
				// The VPN going down arrives while the retry timer is still
				// pending, so the loop gives up on that retry (the stop is the
				// expectation declared above, since this case is superseded by an
				// update) and restarts the service right away, disabled since the
				// tunnel is down: a disabled service forwards no port and does not
				// call the provider at all, which no expectation covers.
				portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
				downUpdate := Settings{
					VPNIsUp: new(false),
					Service: service.Settings{
						PortForwarder: portForwarder,
						Interface:     vpnInterface,
					},
				}
				err = loop.UpdateWith(downUpdate)
				require.NoError(t, err)
				// Back up, the service starts for real this time, and the
				// disabled service in between is stopped on its way out. The VPN
				// was down, so this update is validated as if the program was
				// starting, and the port forwarder name is not asked for.
				err = loop.UpdateWith(vpnUp)
				require.NoError(t, err)
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

// Test_Loop_failedPortForwardRetryDelayReset checks when the retry delay and
// the consecutive failure count go back to their start, so a failing port
// forwarding is retried at the default delay when there is a reason to be, and
// is not when a service crashes as fast as it started. Five attempts run, the
// update asking for the first one and the retry timer for the four others:
// 1 and 2 fail and double the delay,
// 3 succeeds, runs for a while and crashes,
// 4 fails, with a delay depending on how long the service of the attempt 3 ran,
// 5 fails as well, since an update reset the delay before asking for it, and
// sent back the retry the attempt 4 had scheduled.
func Test_Loop_failedPortForwardRetryDelayReset(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// stableRun is true when the service of the attempt 3 reaches
		// [stableServiceRunTime] before its keep alive call fails, which makes
		// the loop forget the failures of the attempts 1 and 2. The fake clock
		// of the test advances the run time, so no test waits for minutes.
		stableRun bool
		// delays are the retry delays announced and armed for each of the five
		// failures. The crash of the attempt 3 is the third entry: it keeps
		// doubling after an immediate crash, and goes back to the default delay
		// once the service has run for long enough.
		delays []time.Duration
	}{
		"crash_asap_keeps_the_backoff": {
			stableRun: false,
			delays: []time.Duration{
				5 * time.Second, 10 * time.Second, // attempts 1 and 2
				20 * time.Second, // crash of the attempt 3
				40 * time.Second, // attempt 4
				5 * time.Second,  // attempt 5, after the update reset
			},
		},
		"crash_after_a_stable_run_resets_the_backoff": {
			stableRun: true,
			delays: []time.Duration{
				5 * time.Second, 10 * time.Second, // attempts 1 and 2
				5 * time.Second,  // crash of the attempt 3, stable run
				10 * time.Second, // attempt 4, counting from the crash again
				5 * time.Second,  // attempt 5, after the update reset
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			const vpnInterface = "tun0"
			const forwardedPort = uint16(45066)
			gateway := netip.MustParseAddr("10.2.0.1")
			internalIP := netip.MustParseAddr("10.2.0.2")
			portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
			client := &http.Client{}
			errPortForward := errors.New("TCP and UDP external ports differ: 45066 and 60808")
			errKeepPort := errors.New("port mapping expired")
			// Part of the error logged with the retry delay, whatever wrapped it
			// on the way from the port forwarder up to the loop. The attempt
			// count is not part of it, the give up test checking it instead.
			retryError := func(failed error, retryDelay time.Duration) string {
				return failed.Error() + " - retrying in " + retryDelay.String()
			}

			// The run time of a service is measured on a clock the test
			// advances by hand, so the stable run of one case is simulated
			// without either case waiting for anything.
			clock := newFakeClock()

			const attempts = 5
			routing := NewMockRouting(ctrl)
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
			// The service runs with the context of the loop, which the test does
			// not have access to
			anyContext := gomock.Any()

			logger.EXPECT().Info("starting").Times(attempts)
			// One expectation per attempt, in the order they run: gomock consumes
			// the expectations of identical arguments in declaration order.
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

			// The failure of the attempt 1 goes back to the update caller, which
			// logs it, so the loop logs the failure of the attempt 2.
			logger.EXPECT().Error(errorContaining{substring: retryError(errPortForward, testCase.delays[1])})
			// Logged by the loop when it receives the keep alive failure of the
			// attempt 3, and waited for before driving the retry it schedules, so
			// the crash is not mistaken for the attempt 4 and their order is not
			// left to the scheduler.
			crashLogged := make(chan struct{})
			logger.EXPECT().Error(errorContaining{substring: retryError(errKeepPort, testCase.delays[2])}).
				DoAndReturn(func(_ string) {
					close(crashLogged)
				})
			logger.EXPECT().Error(errorContaining{substring: retryError(errPortForward, testCase.delays[3])})

			// What the successful attempt 3 does, and cleans up after when the
			// keep alive call fails. The clock is advanced in that call, the
			// latest point where the run time of the service can still be told
			// from the time the loop measured when the service started.
			logger.EXPECT().Info("port forwarded is 45066")
			portAllower.EXPECT().SetAllowedPort(anyContext, forwardedPort, vpnInterface).Return(nil)
			logger.EXPECT().Info("writing port file " + portFilepath)
			portForwarder.EXPECT().KeepPortForward(anyContext, objects).
				DoAndReturn(func(_ context.Context, _ utils.PortForwardObjects) error {
					if testCase.stableRun {
						clock.Advance(stableServiceRunTime)
					}
					return errKeepPort
				})
			portAllower.EXPECT().RemoveAllowedPort(context.Background(), forwardedPort).Return(nil)
			logger.EXPECT().Info("clearing port file " + portFilepath)

			retryTimer := NewMocktimer(ctrl)
			ticks := make(chan time.Time)
			// Armed by each of the five failures.
			retryTimer.EXPECT().C().Return(ticks).Times(attempts)
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
			loop.now = clock.Now
			// The delay the timer is armed with is not the one the loop logs, and
			// a mismatch would leave the test on the announced ladder while the
			// loop waits on another one. The loop is the only writer of the slice,
			// and Stop waits for the run goroutine to end before the test reads it
			// back.
			var armedDelays []time.Duration
			loop.newTimer = func(duration time.Duration) timer {
				armedDelays = append(armedDelays, duration)
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
			require.ErrorContains(t, err, retryError(errPortForward, testCase.delays[0]))

			// Attempts 2 and 3, the later one succeeding and then crashing.
			for range 2 {
				expectTick(t, ticks)
			}

			// The crash of the attempt 3 schedules the retry driving the attempt
			// 4, instead of restarting the service right away.
			expectWait(t, crashLogged, "the keep alive failure to be logged")
			expectTick(t, ticks)

			// The update arrives while the retry of the attempt 4 is pending, and
			// the error of the attempt 5 it triggers goes back to the caller.
			portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
			err = loop.UpdateWith(vpnUp)
			require.ErrorContains(t, err, retryError(errPortForward, testCase.delays[4]))

			err = loop.Stop()
			require.NoError(t, err)
			assert.Equal(t, testCase.delays, armedDelays)
		})
	}
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

// Test_Loop_UpdateWith checks an update asked once the loop has stopped is
// answered at once, instead of waiting for a run which is over: stopping the
// loop cancels the context every waiting UpdateWith call listens on.
func Test_Loop_UpdateWith(t *testing.T) {
	t.Parallel()

	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")
	// The loop starts with the VPN down, so the port forwarding service is
	// never enabled and none of the injected objects is ever used.
	loop := NewLoop(settings.PortForwarding{
		Enabled:        new(true),
		Filepath:       &portFilepath,
		UpCommand:      new(""),
		DownCommand:    new(""),
		ListeningPorts: []uint16{0},
		PortsCount:     1,
	}, nil, nil, nil, nil, nil, os.Getuid(), os.Getgid())

	_, err := loop.Start(t.Context())
	require.NoError(t, err)
	// Stopped even if an assertion below fails this goroutine and leaves the
	// run context alive. A second stop is a no-op.
	t.Cleanup(func() { _ = loop.Stop() })

	err = loop.Stop()
	require.NoError(t, err)

	err = loop.UpdateWith(Settings{VPNIsUp: new(true)})
	assert.ErrorIs(t, err, context.Canceled)
}
