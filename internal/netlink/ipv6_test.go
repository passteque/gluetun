package netlink

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func isIPv6LocallySupported() bool {
	dialer := net.Dialer{Timeout: time.Millisecond}
	_, err := dialer.Dial("tcp6", "[::1]:9999")
	return !strings.HasSuffix(err.Error(), "connect: cannot assign requested address")
}

// Susceptible to TOCTOU but it should be fine for the use case.
func findAvailableTCPPort(t *testing.T) (port uint16) {
	t.Helper()

	config := &net.ListenConfig{}
	listener, err := config.Listen(context.Background(), "tcp", "localhost:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	err = listener.Close()
	require.NoError(t, err)

	addrPort, err := netip.ParseAddrPort(addr)
	require.NoError(t, err)

	return addrPort.Port()
}

func Test_dialAddrThroughFirewall(t *testing.T) {
	t.Parallel()

	const ipv6InternetWorks = false

	testCases := map[string]struct {
		getIPv6CheckAddr  func(t *testing.T) netip.AddrPort
		firewallAddErr    error
		firewallRemoveErr error
		errMessageRegex   func() string
	}{
		"cloudflare.com": {
			getIPv6CheckAddr: func(_ *testing.T) netip.AddrPort {
				return netip.MustParseAddrPort("[2606:4700::6810:84e5]:443")
			},
			errMessageRegex: func() string {
				if ipv6InternetWorks {
					return ""
				}
				return "dialing: dial tcp \\[2606:4700::6810:84e5\\]:443: " +
					"connect: (cannot assign requested address|network is unreachable)"
			},
		},
		"local_server": {
			getIPv6CheckAddr: func(t *testing.T) netip.AddrPort {
				t.Helper()

				network := "tcp6"
				loopback := netip.MustParseAddr("::1")
				if !isIPv6LocallySupported() {
					network = "tcp4"
					loopback = netip.MustParseAddr("127.0.0.1")
				}

				listener, err := net.ListenTCP(network, nil)
				require.NoError(t, err)
				t.Cleanup(func() {
					err := listener.Close()
					require.NoError(t, err)
				})
				addrPort := netip.MustParseAddrPort(listener.Addr().String())
				return netip.AddrPortFrom(loopback, addrPort.Port())
			},
		},
		"no_local_server": {
			getIPv6CheckAddr: func(t *testing.T) netip.AddrPort {
				t.Helper()

				loopback := netip.MustParseAddr("::1")
				if !ipv6InternetWorks {
					loopback = netip.MustParseAddr("127.0.0.1")
				}

				availablePort := findAvailableTCPPort(t)
				return netip.AddrPortFrom(loopback, availablePort)
			},
			errMessageRegex: func() string {
				return "dialing: dial tcp (\\[::1\\]|127\\.0\\.0\\.1):[1-9][0-9]{1,4}: " +
					"connect: connection refused"
			},
		},
		"firewall_add_error": {
			firewallAddErr: errors.New("test error"),
			errMessageRegex: func() string {
				return "accepting output traffic: test error"
			},
		},
		"firewall_remove_error": {
			getIPv6CheckAddr: func(t *testing.T) netip.AddrPort {
				t.Helper()

				network := "tcp4"
				loopback := netip.MustParseAddr("127.0.0.1")
				listener, err := net.ListenTCP(network, nil)
				require.NoError(t, err)
				t.Cleanup(func() {
					err := listener.Close()
					require.NoError(t, err)
				})
				addrPort := netip.MustParseAddrPort(listener.Addr().String())
				return netip.AddrPortFrom(loopback, addrPort.Port())
			},
			firewallRemoveErr: errors.New("test error"),
			errMessageRegex: func() string {
				return "removing output traffic rule: test error"
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			var checkAddr netip.AddrPort
			if testCase.getIPv6CheckAddr != nil {
				checkAddr = testCase.getIPv6CheckAddr(t)
			}

			ctx := context.Background()
			const intf = "eth0"
			firewall := NewMockFirewall(ctrl)
			call := firewall.EXPECT().AcceptOutput(ctx, "tcp", intf,
				checkAddr.Addr(), checkAddr.Port(), false).
				Return(testCase.firewallAddErr)
			if testCase.firewallAddErr == nil {
				firewall.EXPECT().AcceptOutput(ctx, "tcp", intf,
					checkAddr.Addr(), checkAddr.Port(), true).
					Return(testCase.firewallRemoveErr).After(call)
			}

			err := dialAddrThroughFirewall(ctx, intf, checkAddr, firewall)
			var errMessageRegex string
			if testCase.errMessageRegex != nil {
				errMessageRegex = testCase.errMessageRegex()
			}
			if errMessageRegex == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Regexp(t, errMessageRegex, err.Error())
			}
		})
	}
}
