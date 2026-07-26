package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

// Test_Service_onPortsChanged checks that adopting ports reassigned by the
// gateway closes the firewall for the previous port before opening the new one,
// and leaves the port forwarded file holding the new port. Leaving the previous
// port allowed would keep a hole open for a port that is no longer forwarded.
func Test_Service_onPortsChanged(t *testing.T) {
	t.Parallel()

	const (
		vpnInterface = "tun0"
		previousPort = uint16(37928)
		newPort      = uint16(60557)
	)

	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info(gomock.Any()).AnyTimes()
	logger.EXPECT().Debug(gomock.Any()).AnyTimes()

	portAllower := NewMockPortAllower(ctrl)
	gomock.InOrder(
		// The previous port must be blocked before the new one is allowed.
		portAllower.EXPECT().RemoveAllowedPort(gomock.Any(), previousPort).Return(nil),
		portAllower.EXPECT().SetAllowedPort(gomock.Any(), newPort, vpnInterface).Return(nil),
	)

	service := &Service{
		ports: []uint16{previousPort},
		settings: Settings{
			Filepath:       portFilepath,
			Interface:      vpnInterface,
			ListeningPorts: []uint16{0},
		},
		portAllower: portAllower,
		logger:      logger,
		puid:        os.Getuid(),
		pgid:        os.Getgid(),
	}

	err := service.onPortsChanged(context.Background(), map[uint16]uint16{newPort: newPort})
	require.NoError(t, err)

	assert.Equal(t, []uint16{newPort}, service.GetPortsForwarded())

	written, err := os.ReadFile(portFilepath)
	require.NoError(t, err)
	assert.Equal(t, "60557", string(written))
}

// Test_Service_onPortsChanged_keepsPreviousPortsOnFailure checks that a failure
// to open the new port does not silently leave the service reporting ports it
// is no longer forwarding.
func Test_Service_onPortsChanged_keepsPreviousPortsOnFailure(t *testing.T) {
	t.Parallel()

	const (
		vpnInterface = "tun0"
		previousPort = uint16(37928)
		newPort      = uint16(60557)
	)

	portFilepath := filepath.Join(t.TempDir(), "forwarded_port")

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info(gomock.Any()).AnyTimes()
	logger.EXPECT().Debug(gomock.Any()).AnyTimes()

	errAllow := assert.AnError
	portAllower := NewMockPortAllower(ctrl)
	portAllower.EXPECT().RemoveAllowedPort(gomock.Any(), previousPort).Return(nil)
	portAllower.EXPECT().SetAllowedPort(gomock.Any(), newPort, vpnInterface).Return(errAllow)

	service := &Service{
		ports: []uint16{previousPort},
		settings: Settings{
			Filepath:       portFilepath,
			Interface:      vpnInterface,
			ListeningPorts: []uint16{0},
		},
		portAllower: portAllower,
		logger:      logger,
		puid:        os.Getuid(),
		pgid:        os.Getgid(),
	}

	err := service.onPortsChanged(context.Background(), map[uint16]uint16{newPort: newPort})
	require.Error(t, err)
	assert.ErrorIs(t, err, errAllow)

	// The previous port was already blocked, so nothing must still be reported
	// as forwarded.
	assert.Empty(t, service.GetPortsForwarded())
}
