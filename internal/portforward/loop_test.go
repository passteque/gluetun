package portforward

import (
	"context"
	"errors"
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

func expectWait(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-hangContext(t).Done():
		t.Fatalf("timed out waiting for %s", description)
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
	}{
		"retried_when_timer_fires": {
			retryByTimer: true,
		},
		"retried_by_update_dropping_timer": {
			retryByTimer: false,
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
			retryTimer.EXPECT().C().Return(ticks).Times(1)
			if !testCase.retryByTimer {
				// Registered before the update below: the loop stops the
				// pending retry as it processes the update. Stopping it is what
				// prevents a second service start, remapping the port forwarded.
				retryTimer.EXPECT().Stop().Times(1)
			}

			loop := NewLoop(settings.PortForwarding{
				Enabled:        new(true),
				Filepath:       &portFilepath,
				UpCommand:      new(""),
				DownCommand:    new(""),
				ListeningPorts: []uint16{0},
				PortsCount:     1,
			}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
			loop.newTimer = func(duration time.Duration) timer {
				assert.Equal(t, retryDelay, duration)
				return retryTimer
			}
			_, err := loop.Start(t.Context())
			require.NoError(t, err)

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

			if testCase.retryByTimer {
				// Makes the pending retry fire. The loop is blocked on the timer,
				// so the send only succeeds once the loop waits for it.
				select {
				case ticks <- time.Now():
				case <-hangContext(t).Done():
					t.Fatal("timed out waiting for the loop to wait on the retry timer")
				}
			} else {
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
		})
	}
}
