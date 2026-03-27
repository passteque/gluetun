package tcp

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/firewall"
	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/routing"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// testFirewall must be global to prevent parallel tests from interfering
// with each other since they would interact with the same filter table.
// The first test to use should initialize it, and the rest will reuse it.
var (
	testFirewall     *firewall.Config //nolint:gochecknoglobals
	testFirewallOnce sync.Once        //nolint:gochecknoglobals
)

// getFirewall returns a Firewall instance, initializing it if needed. If
// iptables is not supported, it skips the test.
func getFirewall(t *testing.T) *firewall.Config {
	t.Helper()

	testFirewallOnce.Do(func() {
		noopLogger := &noopLogger{}
		cmder := command.New()
		var err error
		testFirewall, err = firewall.NewConfig(t.Context(), noopLogger, noopLogger, cmder, nil, nil)
		if errors.Is(err, iptables.ErrNotSupported) {
			t.Skip("iptables not installed, skipping TCP PMTUD tests")
		}
		require.NoError(t, err, "creating firewall config")
	})
	if testFirewall == nil {
		t.Skip("iptables not installed, skipping TCP PMTUD tests")
	}
	return testFirewall
}

type noopLogger struct{}

func (l *noopLogger) Patch(_ ...log.Option)     {}
func (l *noopLogger) Debug(_ string)            {}
func (l *noopLogger) Debugf(_ string, _ ...any) {}
func (l *noopLogger) Info(_ string)             {}
func (l *noopLogger) Warn(_ string)             {}
func (l *noopLogger) Warnf(_ string, _ ...any)  {}
func (l *noopLogger) Error(_ string)            {}

var errRouteNotFound = errors.New("route not found")

func findLoopbackMTU(netlinker *netlink.NetLink) (mtu uint32, err error) {
	routes, err := netlinker.RouteList(netlink.FamilyV4)
	if err != nil {
		return 0, fmt.Errorf("getting routes list: %w", err)
	}
	for _, route := range routes {
		if route.Dst.IsValid() && route.Dst.Addr().IsLoopback() {
			link, err := netlinker.LinkByIndex(route.LinkIndex)
			if err != nil {
				return 0, fmt.Errorf("getting link by index: %w", err)
			}
			// Quirk: make sure it is maximum 65535, and not i.e. 65536
			// or the IP header 16 bits will fail to fit that packet length value.
			const maxMTU = 65535
			return min(link.MTU, maxMTU), nil
		}
	}
	return 0, fmt.Errorf("%w: no loopback route found", errRouteNotFound)
}

func findDefaultRouteMTU(netlinker *netlink.NetLink) (mtu uint32, err error) {
	noopLogger := &noopLogger{}
	routing := routing.New(netlinker, noopLogger)
	defaultRoutes, err := routing.DefaultRoutes()
	if err != nil {
		return 0, fmt.Errorf("getting default routes: %w", err)
	}
	families := []uint8{constants.AF_INET, constants.AF_INET6}
	for _, family := range families {
		for _, route := range defaultRoutes {
			if route.Family != family {
				continue
			}
			link, err := netlinker.LinkByName(route.NetInterface)
			if err != nil {
				return 0, fmt.Errorf("getting link by name: %w", err)
			}
			mtu = max(mtu, link.MTU)
		}
	}
	if mtu == 0 {
		return 0, fmt.Errorf("%w: no default route found", errRouteNotFound)
	}
	return mtu, nil
}

func reserveClosedPort(t *testing.T) (port uint16) {
	t.Helper()

	fd, err := unix.Socket(constants.AF_INET, constants.SOCK_STREAM, constants.IPPROTO_TCP)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := unix.Close(fd)
		assert.NoError(t, err)
	})

	addr := &unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}

	err = unix.Bind(fd, addr)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}

	sockAddr, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}

	sockAddr4, ok := sockAddr.(*unix.SockaddrInet4)
	if !ok {
		_ = unix.Close(fd)
		t.Fatal("not an IPv4 address")
	}

	return uint16(sockAddr4.Port) //nolint:gosec
}
