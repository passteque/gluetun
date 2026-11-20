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
	"github.com/qdm12/gluetun/internal/provider/utils"
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

	cleanedUpCh := make(chan struct{})
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("starting").Times(1)
	logger.EXPECT().Info("port forwarded is 1234").Times(1)
	logger.EXPECT().Info("writing port file " + portFilePath).Times(1)
	// Cleared by the crash cleanup only. The Stop call finds the service released
	// by the crashed goroutine, so it neither logs nor cleans up a second time.
	logger.EXPECT().Info("clearing port file " + portFilePath).
		DoAndReturn(func(_ string) { close(cleanedUpCh) }).Times(1)

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

	// The port file cleared tells the crash cleanup is done: the goroutine closes
	// the done channel before cleaning up, and the ports are set to none just
	// before that log, so the Stop call below finds nothing left to do.
	cleanupDeadline := time.NewTimer(time.Second)
	defer cleanupDeadline.Stop()
	select {
	case <-cleanedUpCh:
	case <-cleanupDeadline.C:
		t.Fatal("keep port goroutine did not clean the service up after crashing")
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

// Test_Service_Start_keepPortCrashWaitingForStartStopMutex checks a keep port
// goroutine which crashes while the start stop mutex is held, like a Stop call
// holds it for the whole of its run, releases the service anyway. The goroutine
// closes the done channel before waiting for the mutex, since a Stop call waits
// on that channel while holding the mutex: waiting for the mutex first would
// have them wait for one another forever, and a Stop call which never returns
// leaves the program running with a service nobody can stop.
func Test_Service_Start_keepPortCrashWaitingForStartStopMutex(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	portFilePath := filepath.Join(t.TempDir(), "forwarded_port")
	runCtx := t.Context()

	cleanedUpCh := make(chan struct{})
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("starting").Times(1)
	logger.EXPECT().Info("port forwarded is 1234").Times(1)
	logger.EXPECT().Info("writing port file " + portFilePath).Times(1)
	// Cleaned up once, by the crashed goroutine which owns the service until the
	// Stop call below finds it released.
	logger.EXPECT().Info("clearing port file " + portFilePath).
		DoAndReturn(func(_ string) { close(cleanedUpCh) }).Times(1)

	portAllower := NewMockPortAllower(ctrl)
	portAllower.EXPECT().SetAllowedPort(runCtx, uint16(1234), "tun0").Return(nil).Times(1)
	portAllower.EXPECT().RemoveAllowedPort(context.Background(), uint16(1234)).Return(nil).Times(1)

	gateway := netip.MustParseAddr("10.0.0.1")
	assignedIP := netip.MustParseAddr("10.0.0.2")
	routing := NewMockRouting(ctrl)
	routing.EXPECT().VPNLocalGatewayIP("tun0").Return(gateway, nil).Times(1)
	routing.EXPECT().AssignedIP("tun0", netlink.FamilyV4).Return(assignedIP, nil).Times(1)

	errKeepPortForward := errors.New("port forward keep alive error")
	crashNow := make(chan struct{})
	portForwarder := NewMockPortForwarder(ctrl)
	portForwarder.EXPECT().PortForward(runCtx, gomock.Any()).
		Return(map[uint16]uint16{1234: 1234}, nil).Times(1)
	portForwarder.EXPECT().KeepPortForward(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ utils.PortForwardObjects) error {
			<-crashNow
			return errKeepPortForward
		}).Times(1)

	settings := Settings{
		Enabled:        new(true),
		PortForwarder:  portForwarder,
		Filepath:       portFilePath,
		Interface:      "tun0",
		ListeningPorts: []uint16{0}, // user redirection disabled
	}
	srv := New(settings, routing, nil, portAllower, logger, nil,
		os.Getuid(), os.Getgid())

	// The run error channel is left unread, the crash happening while the port
	// forwarding loop still believes it owns the service.
	_, err := srv.Start(runCtx)
	require.NoError(t, err)

	srv.startStopMutex.Lock()
	close(crashNow)

	releaseDeadline := time.NewTimer(time.Second)
	defer releaseDeadline.Stop()
	select {
	case <-srv.keepPortDoneCh:
	case <-releaseDeadline.C:
		srv.startStopMutex.Unlock()
		t.Fatal("the keep port goroutine waits for the start stop mutex, held by the " +
			"test here as a Stop call would hold it, before releasing the service")
	}
	srv.startStopMutex.Unlock()

	// The crashed goroutine is the only one waiting for the start stop mutex, so
	// it is the one cleaning the service up, before any Stop call runs.
	cleanupDeadline := time.NewTimer(time.Second)
	defer cleanupDeadline.Stop()
	select {
	case <-cleanedUpCh:
	case <-cleanupDeadline.C:
		t.Fatal("the keep port goroutine did not clean the service up once it got " +
			"the start stop mutex")
	}

	stoppedCh := make(chan error, 1)
	go func() { stoppedCh <- srv.Stop() }()

	stopDeadline := time.NewTimer(time.Second)
	defer stopDeadline.Stop()
	select {
	case err := <-stoppedCh:
		assert.NoError(t, err)
	case <-stopDeadline.C:
		t.Fatal("Stop is blocked by the keep port goroutine crashing at the same time")
	}

	assert.Empty(t, srv.GetPortsForwarded())

	fileData, readErr := os.ReadFile(portFilePath)
	assert.NoError(t, readErr)
	assert.Empty(t, string(fileData))
}
