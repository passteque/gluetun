package service

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

// Test_Service_Start_keepPortCrashReported checks the service cleans up and
// reports the failure of the keep port call on the run error channel the Start
// call returns, which the port forwarding loop reads while it runs.
func Test_Service_Start_keepPortCrashReported(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	portFilePath := filepath.Join(t.TempDir(), "forwarded_port")
	runCtx := t.Context()

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("starting").Times(1)
	logger.EXPECT().Info("port forwarded is 1234").Times(1)
	logger.EXPECT().Info("writing port file " + portFilePath).Times(1)
	logger.EXPECT().Info("clearing port file " + portFilePath).Times(1)

	portAllower := NewMockPortAllower(ctrl)
	portAllower.EXPECT().SetAllowedPort(runCtx, uint16(1234), "tun0").Return(nil).Times(1)
	portAllower.EXPECT().RemoveAllowedPort(context.Background(), uint16(1234)).Return(nil).Times(1)

	gateway := netip.MustParseAddr("10.0.0.1")
	assignedIP := netip.MustParseAddr("10.0.0.2")
	routing := NewMockRouting(ctrl)
	routing.EXPECT().VPNLocalGatewayIP("tun0").Return(gateway, nil).Times(1)
	routing.EXPECT().AssignedIP("tun0", netlink.FamilyV4).Return(assignedIP, nil).Times(1)

	errKeepPortForward := errors.New("port forward keep alive error")
	portForwarder := NewMockPortForwarder(ctrl)
	portForwarder.EXPECT().PortForward(runCtx, gomock.Any()).
		Return(map[uint16]uint16{1234: 1234}, nil).Times(1)
	// The keep port call runs with a context of its own, canceled by Stop,
	// which the test cannot build to match it.
	portForwarder.EXPECT().KeepPortForward(gomock.Any(), gomock.Any()).
		Return(errKeepPortForward).Times(1)

	settings := Settings{
		Enabled:        new(true),
		PortForwarder:  portForwarder,
		Filepath:       portFilePath,
		Interface:      "tun0",
		ListeningPorts: []uint16{0}, // user redirection disabled
	}
	srv := New(settings, routing, nil, portAllower, logger, nil,
		os.Getuid(), os.Getgid())

	runError, err := srv.Start(runCtx)
	require.NoError(t, err)

	errDeadline := time.NewTimer(time.Second)
	defer errDeadline.Stop()
	var keepPortErr error
	select {
	case keepPortErr = <-runError:
	case <-errDeadline.C:
		t.Fatal("keep port call failure not reported on the run error channel")
	}
	assert.ErrorIs(t, keepPortErr, errKeepPortForward)

	// The goroutine has to reach the end of its run and clear the ports, once
	// the error it reports has been read.
	doneDeadline := time.NewTimer(time.Second)
	defer doneDeadline.Stop()
	select {
	case <-srv.keepPortDoneCh:
	case <-doneDeadline.C:
		t.Fatal("keep port goroutine did not finish after reporting its failure")
	}

	assert.Empty(t, srv.GetPortsForwarded())
	assert.NoError(t, srv.Stop())

	fileData, readErr := os.ReadFile(portFilePath)
	assert.NoError(t, readErr)
	assert.Empty(t, string(fileData))
}

// Test_Service_Start_keepPortCrashWithoutRunErrorReader checks a failing keep
// port call does not prevent the service from being stopped when nobody reads
// the run error channel of Start anymore, which happens once the port
// forwarding loop has left the service behind by stopping on a fatal error.
// The crashed goroutine releases the service before reporting, so the Stop call
// finds nothing left to clean up and only releases the goroutine.
func Test_Service_Start_keepPortCrashWithoutRunErrorReader(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	portFilePath := filepath.Join(t.TempDir(), "forwarded_port")
	runCtx := t.Context()

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("starting").Times(1)
	logger.EXPECT().Info("port forwarded is 1234").Times(1)
	logger.EXPECT().Info("writing port file " + portFilePath).Times(1)
	// Cleared by the crash cleanup only. The Stop call finds the service released
	// by the crashed goroutine, so it neither logs nor cleans up a second time.
	logger.EXPECT().Info("clearing port file " + portFilePath).Times(1)

	portAllower := NewMockPortAllower(ctrl)
	portAllower.EXPECT().SetAllowedPort(runCtx, uint16(1234), "tun0").Return(nil).Times(1)
	// Only the crash cleanup removes the allowed port, since the Stop call finds
	// the service already released.
	portAllower.EXPECT().RemoveAllowedPort(context.Background(), uint16(1234)).Return(nil).Times(1)

	gateway := netip.MustParseAddr("10.0.0.1")
	assignedIP := netip.MustParseAddr("10.0.0.2")
	routing := NewMockRouting(ctrl)
	routing.EXPECT().VPNLocalGatewayIP("tun0").Return(gateway, nil).Times(1)
	routing.EXPECT().AssignedIP("tun0", netlink.FamilyV4).Return(assignedIP, nil).Times(1)

	errKeepPortForward := errors.New("port forward keep alive error")
	portForwarder := NewMockPortForwarder(ctrl)
	portForwarder.EXPECT().PortForward(runCtx, gomock.Any()).
		Return(map[uint16]uint16{1234: 1234}, nil).Times(1)
	// The keep port call runs with a context of its own, canceled by Stop,
	// which the test cannot build to match it.
	portForwarder.EXPECT().KeepPortForward(gomock.Any(), gomock.Any()).
		Return(errKeepPortForward).Times(1)

	settings := Settings{
		Enabled:        new(true),
		PortForwarder:  portForwarder,
		Filepath:       portFilePath,
		Interface:      "tun0",
		ListeningPorts: []uint16{0}, // user redirection disabled
	}
	srv := New(settings, routing, nil, portAllower, logger, nil,
		os.Getuid(), os.Getgid())

	// The run error channel is left unread, like the port forwarding loop
	// leaves the service behind once it has stopped.
	_, err := srv.Start(runCtx)
	require.NoError(t, err)

	// The keep port goroutine closes the done channel once it has cleaned the
	// service up, before it waits to report a failure nobody reads. Reading the
	// port file would not tell as much, since the cleanup clears it before the
	// goroutine releases the service.
	crashDeadline := time.NewTimer(time.Second)
	defer crashDeadline.Stop()
	select {
	case <-srv.keepPortDoneCh:
	case <-crashDeadline.C:
		t.Fatal("keep port goroutine did not release the service after crashing")
	}

	stoppedCh := make(chan error, 1)
	go func() { stoppedCh <- srv.Stop() }()

	stopDeadline := time.NewTimer(time.Second)
	defer stopDeadline.Stop()
	select {
	case err := <-stoppedCh:
		assert.NoError(t, err)
	case <-stopDeadline.C:
		t.Fatal("Stop is blocked by the keep port goroutine reporting its crash")
	}

	assert.Empty(t, srv.GetPortsForwarded())

	fileData, readErr := os.ReadFile(portFilePath)
	assert.NoError(t, readErr)
	assert.Empty(t, string(fileData))
}
