package portforward

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/synctest"
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

func Test_Loop_failedFirstPortForward(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		updateAgainAfter time.Duration // zero for no second update
		forwardedAfter   time.Duration
	}{
		"retried": {
			forwardedAfter: 5 * time.Second,
		},
		"pending_retry_dropped_by_update": {
			updateAgainAfter: time.Second,
			forwardedAfter:   time.Second,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				anyContext := gomock.AssignableToTypeOf(reflect.TypeFor[context.Context]())

				const vpnInterface = "tun0"
				const forwardedPort = uint16(45066)
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

				// The first port forwarding fails, the next one succeeds and is kept until the loop stops
				logger.EXPECT().Info("starting").Times(2)
				failed := portForwarder.EXPECT().PortForward(anyContext, objects).
					Return(nil, errors.New("TCP and UDP external ports differ: 45066 and 60808"))
				forwarded := make(chan struct{})
				portForwarder.EXPECT().PortForward(anyContext, objects).After(failed).
					DoAndReturn(func(context.Context, utils.PortForwardObjects) (map[uint16]uint16, error) {
						close(forwarded)
						return map[uint16]uint16{forwardedPort: forwardedPort}, nil
					})
				logger.EXPECT().Info("port forwarded is 45066")
				portAllower.EXPECT().SetAllowedPort(anyContext, forwardedPort, vpnInterface).Return(nil)
				logger.EXPECT().Info("writing port file " + portFilepath)
				portForwarder.EXPECT().KeepPortForward(anyContext, objects).
					DoAndReturn(func(ctx context.Context, _ utils.PortForwardObjects) error {
						<-ctx.Done()
						return ctx.Err()
					})
				logger.EXPECT().Info("stopping")
				portAllower.EXPECT().RemoveAllowedPort(context.Background(), forwardedPort).Return(nil)
				logger.EXPECT().Info("clearing port file " + portFilepath)

				loop := NewLoop(settings.PortForwarding{
					Enabled:        new(true),
					Filepath:       &portFilepath,
					UpCommand:      new(""),
					DownCommand:    new(""),
					ListeningPorts: []uint16{0},
					PortsCount:     1,
				}, routing, client, portAllower, logger, nil, os.Getuid(), os.Getgid())
				_, err := loop.Start(t.Context())
				require.NoError(t, err)

				vpnUp := Settings{
					VPNIsUp: new(true),
					Service: service.Settings{
						PortForwarder: portForwarder,
						Interface:     vpnInterface,
					},
				}
				start := time.Now()
				err = loop.UpdateWith(vpnUp)
				require.ErrorContains(t, err, "TCP and UDP external ports differ")
				assert.ErrorContains(t, err, "retrying in 5s")

				if testCase.updateAgainAfter > 0 {
					portForwarder.EXPECT().Name().Return(providers.Protonvpn) // settings validation
					time.Sleep(testCase.updateAgainAfter)
					err = loop.UpdateWith(vpnUp)
					require.NoError(t, err)
				}

				<-forwarded
				synctest.Wait()
				assert.Equal(t, testCase.forwardedAfter, time.Since(start))
				assert.Equal(t, []uint16{forwardedPort}, loop.GetPortsForwarded())

				// No other start remaps the port: the mocks fail on any unexpected call
				time.Sleep(time.Minute)
				synctest.Wait()

				err = loop.Stop()
				require.NoError(t, err)
			})
		})
	}
}
