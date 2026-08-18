package customvpn

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
)

type testStarter struct {
	stdout    chan string
	stderr    chan string
	waitError chan error
	startErr  error

	mutex sync.Mutex
	cmd   *exec.Cmd
}

func (s *testStarter) Start(cmd *exec.Cmd) (
	stdoutLines, stderrLines <-chan string,
	waitError <-chan error, startErr error,
) {
	s.mutex.Lock()
	s.cmd = cmd
	s.mutex.Unlock()
	if s.startErr != nil {
		return nil, nil, nil, s.startErr
	}
	return s.stdout, s.stderr, s.waitError, nil
}

func (s *testStarter) startedCmd() *exec.Cmd {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.cmd
}

type testLogger struct {
	mutex      sync.Mutex
	infoLines  []string
	errorLines []string
}

func (l *testLogger) Info(s string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.infoLines = append(l.infoLines, s)
}

func (l *testLogger) Error(s string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.errorLines = append(l.errorLines, s)
}

type testNetLinker struct {
	link      netlink.Link
	linkErr   error
	addresses []netip.Prefix
	routes    []netlink.Route
}

func (n *testNetLinker) LinkByName(string) (link netlink.Link, err error) {
	return n.link, n.linkErr
}

func (n *testNetLinker) AddrList(uint32, uint8) (
	addresses []netip.Prefix, err error,
) {
	return n.addresses, nil
}

func (n *testNetLinker) RouteList(uint8) (routes []netlink.Route, err error) {
	return n.routes, nil
}

func newTestSettings(args, readyLine string) settings.CustomVPN {
	return settings.CustomVPN{
		Binary:           "/path/to/custom-vpn",
		Args:             new(args),
		Interface:        "tun0",
		ReadyLine:        new(readyLine),
		EndpointIP:       netip.MustParseAddr("1.2.3.4"),
		EndpointPort:     1194,
		EndpointProtocol: "udp",
	}
}

func receiveReadyWithTimeout(t *testing.T, ready <-chan struct{}, failureMessage string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal(failureMessage)
	}
}

func receiveErrorWithTimeout(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(time.Second):
		t.Fatal("runner did not exit")
		panic("unreachable")
	}
}

func Test_Runner_Run_ready_line_matched(t *testing.T) {
	t.Parallel()

	starter := &testStarter{
		stdout:    make(chan string),
		stderr:    make(chan string),
		waitError: make(chan error),
	}
	logger := &testLogger{}
	runnerSettings := newTestSettings("--config /etc/custom.conf", "[Cc]onnection established")
	runner := NewRunner(runnerSettings, starter, &testNetLinker{}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	starter.stdout <- "starting up"
	starter.stderr <- "some warning"
	starter.stdout <- "the connection established successfully"

	receiveReadyWithTimeout(t, ready, "tunnel was not signaled as ready")

	// A second matching line must not signal readiness again.
	starter.stdout <- "the Connection established again"

	close(starter.stdout)
	close(starter.stderr)
	errProcess := errors.New("exit status 2")
	starter.waitError <- errProcess

	err := receiveErrorWithTimeout(t, errCh)
	assert.ErrorIs(t, err, errProcess)

	select {
	case <-ready:
		t.Fatal("tunnel was signaled as ready more than once")
	default:
	}

	expectedArgs := []string{"/path/to/custom-vpn", "--config", "/etc/custom.conf"}
	assert.Equal(t, expectedArgs, starter.startedCmd().Args)
	assert.Contains(t, logger.infoLines, "starting up")
	assert.Contains(t, logger.errorLines, "some warning")
}

func Test_Runner_Run_process_exits_before_ready(t *testing.T) {
	t.Parallel()

	starter := &testStarter{
		stdout:    make(chan string),
		stderr:    make(chan string),
		waitError: make(chan error),
	}
	runnerSettings := newTestSettings("", "line never matched")
	runner := NewRunner(runnerSettings, starter, &testNetLinker{}, &testLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	starter.stdout <- "starting up"
	close(starter.stdout)
	close(starter.stderr)
	errProcess := errors.New("exit status 1")
	starter.waitError <- errProcess

	err := receiveErrorWithTimeout(t, errCh)
	assert.ErrorIs(t, err, errProcess)

	select {
	case <-ready:
		t.Fatal("tunnel was signaled as ready")
	default:
	}
}

func Test_Runner_Run_interface_polling_ready(t *testing.T) {
	t.Parallel()

	starter := &testStarter{
		stdout:    make(chan string),
		stderr:    make(chan string),
		waitError: make(chan error),
	}
	netLinker := &testNetLinker{
		link:      netlink.Link{Index: 1, Name: "tun0"},
		addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		routes:    []netlink.Route{{LinkIndex: 1}},
	}
	runnerSettings := newTestSettings("", "")
	runner := NewRunner(runnerSettings, starter, netLinker, &testLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	receiveReadyWithTimeout(t, ready, "tunnel was not signaled as ready")

	close(starter.stdout)
	close(starter.stderr)
	errProcess := errors.New("exit status 2")
	starter.waitError <- errProcess

	err := receiveErrorWithTimeout(t, errCh)
	assert.ErrorIs(t, err, errProcess)
}

func Test_Runner_Run_interface_polling_waits_for_the_route(t *testing.T) {
	t.Parallel()

	// An address on the interface is not enough: path MTU discovery lists the
	// routes of the interface and port forwarding reads the VPN gateway out of
	// them, so a tunnel announced between the address and the route makes both
	// fail on a client that was about to work.
	starter := &testStarter{
		stdout:    make(chan string),
		stderr:    make(chan string),
		waitError: make(chan error),
	}
	netLinker := &testNetLinker{
		link:      netlink.Link{Index: 1, Name: "tun0"},
		addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		routes:    []netlink.Route{{LinkIndex: 2}}, // another interface
	}
	runnerSettings := newTestSettings("", "")
	runner := NewRunner(runnerSettings, starter, netLinker, &testLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	const pollPeriods = 5 * 200 * time.Millisecond
	select {
	case <-ready:
		t.Fatal("tunnel was signaled as ready with no route through its interface")
	case <-time.After(pollPeriods):
	}

	cancel()
	close(starter.stdout)
	close(starter.stderr)
	starter.waitError <- nil
}

func Test_Runner_Run_start_error(t *testing.T) {
	t.Parallel()

	errStart := errors.New("permission denied")
	starter := &testStarter{startErr: errStart}
	runnerSettings := newTestSettings("", "")
	runner := NewRunner(runnerSettings, starter, &testNetLinker{}, &testLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	err := receiveErrorWithTimeout(t, errCh)
	assert.ErrorIs(t, err, errStart)
	assert.ErrorContains(t, err, "starting binary")
}

func Test_Runner_Run_bad_arguments(t *testing.T) {
	t.Parallel()

	starter := &testStarter{}
	runnerSettings := newTestSettings("--config 'unterminated", "")
	runner := NewRunner(runnerSettings, starter, &testNetLinker{}, &testLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error)
	ready := make(chan struct{})
	go runner.Run(ctx, errCh, ready)

	err := receiveErrorWithTimeout(t, errCh)
	assert.ErrorContains(t, err, "splitting arguments")
	assert.Nil(t, starter.startedCmd())
}
