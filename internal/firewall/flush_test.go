package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qdm12/gluetun/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNetlinker is a test double for the Netlinker interface.
type testNetlinker struct {
	flushConntrackErr   error
	flushConntrackCalls int
}

func (n *testNetlinker) FlushConntrack() error {
	n.flushConntrackCalls++
	return n.flushConntrackErr
}

// testImpl is a test double for the firewallImpl interface.
// Any method that is not explicitly stubbed below panics if called.
type testImpl struct {
	firewallImpl

	acceptNewTrafficErr error
	rejectTrafficErr    error
	dropTrafficErr      error

	mu            sync.Mutex
	calls         []string
	localPrefixes []netip.Prefix
}

func (m *testImpl) record(call string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, call)
}

func (m *testImpl) callsSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

func (m *testImpl) AcceptOutputPublicOnlyNewTraffic(_ context.Context,
	localPrefixes []netip.Prefix,
) error {
	m.mu.Lock()
	m.localPrefixes = localPrefixes
	m.mu.Unlock()
	m.record("accept-new-traffic")
	return m.acceptNewTrafficErr
}

func (m *testImpl) RejectOutputPublicTraffic(_ context.Context,
	localPrefixes []netip.Prefix, remove bool,
) error {
	m.mu.Lock()
	m.localPrefixes = localPrefixes
	m.mu.Unlock()
	m.record(fmt.Sprintf("reject-traffic-%t", remove))
	return m.rejectTrafficErr
}

func (m *testImpl) DropOutputPublicTraffic(_ context.Context,
	localPrefixes []netip.Prefix, remove bool,
) error {
	m.mu.Lock()
	m.localPrefixes = localPrefixes
	m.mu.Unlock()
	m.record(fmt.Sprintf("drop-traffic-%t", remove))
	return m.dropTrafficErr
}

// testLogger is a test double for the Logger interface that records the entries.
type testLogger struct {
	mu      sync.Mutex
	entries []string // "level: message"
}

func (l *testLogger) add(level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, level+": "+message)
}

func (l *testLogger) Debug(s string)            { l.add("debug", s) }
func (l *testLogger) Debugf(f string, a ...any) { l.add("debug", fmt.Sprintf(f, a...)) }
func (l *testLogger) Info(s string)             { l.add("info", s) }
func (l *testLogger) Warn(s string)             { l.add("warn", s) }
func (l *testLogger) Warnf(f string, a ...any)  { l.add("warn", fmt.Sprintf(f, a...)) }
func (l *testLogger) Error(s string)            { l.add("error", s) }

func (l *testLogger) entriesContaining(level, substring string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	matching := make([]string, 0, len(l.entries))
	for _, entry := range l.entries {
		if strings.HasPrefix(entry, level+": ") && strings.Contains(entry, substring) {
			matching = append(matching, entry)
		}
	}
	return matching
}

func Test_flushExistingConnections(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		flushConntrackErr   error
		acceptNewTrafficErr error
		rejectTrafficErr    error
		dropTrafficErr      error
		localNetworks       []routing.LocalNetwork

		expectedCalls          []string
		expectedFallbackDebugs int
		expectedWarnSubstr     []string
	}{
		"flush conntrack succeeds": {
			// No iptables-based fallback should be used.
			expectedCalls: []string{},
		},
		// On older kernels (4.4.x), the conntrack netlink delete message is not
		// supported, so flushing fails with a raw netlink error, and the module
		// probe may have succeeded (see https://github.com/qdm12/gluetun/issues/3152).
		// The fallback to the iptables-based methods must still kick in.
		"flush conntrack fails with raw netlink error": {
			flushConntrackErr: errors.New("querying netlink request: netlink receive: invalid argument"),
			localNetworks: []routing.LocalNetwork{
				{IPNet: netip.MustParsePrefix("192.168.1.0/24"), InterfaceName: "eth0"},
				// Globally routed local network (not a private prefix).
				{IPNet: netip.MustParsePrefix("2001:db8:abcd::/48"), InterfaceName: "eth0"},
			},
			expectedCalls:          []string{"accept-new-traffic"},
			expectedFallbackDebugs: 1,
		},
		"flush conntrack and accept-new-traffic fail, reject works": {
			flushConntrackErr:   errors.New("querying netlink request: netlink receive: invalid argument"),
			acceptNewTrafficErr: errors.New("missing kernel module: xt_connmark"),
			localNetworks:       []routing.LocalNetwork{{IPNet: netip.MustParsePrefix("10.0.0.0/8")}},
			expectedCalls: []string{
				"accept-new-traffic",
				"reject-traffic-false",
				"reject-traffic-true",
			},
			expectedFallbackDebugs: 2,
		},
		"all methods fail, warning is logged and no error is returned": {
			flushConntrackErr:   errors.New("querying netlink request: netlink receive: invalid argument"),
			acceptNewTrafficErr: errors.New("missing kernel module: xt_connmark"),
			rejectTrafficErr:    errors.New("missing kernel module: xt_reject"),
			dropTrafficErr:      errors.New("missing kernel module: xt_conntrack"),
			expectedCalls: []string{
				"accept-new-traffic",
				"reject-traffic-false",
				"drop-traffic-false",
			},
			expectedFallbackDebugs: 3,
			expectedWarnSubstr: []string{
				"flushing existing connections failed",
				"netlink receive: invalid argument",
				"missing kernel module: xt_conntrack",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			netlinker := &testNetlinker{flushConntrackErr: testCase.flushConntrackErr}
			impl := &testImpl{
				acceptNewTrafficErr: testCase.acceptNewTrafficErr,
				rejectTrafficErr:    testCase.rejectTrafficErr,
				dropTrafficErr:      testCase.dropTrafficErr,
			}
			logger := &testLogger{}
			config := &Config{
				netlinker:     netlinker,
				impl:          impl,
				logger:        logger,
				localNetworks: testCase.localNetworks,
			}

			// Must not fail, no matter what the tries return.
			config.flushExistingConnections(t.Context())

			// The conntrack flush is always tried first.
			require.Equal(t, 1, netlinker.flushConntrackCalls)

			assert.ElementsMatch(t, testCase.expectedCalls, impl.callsSnapshot())

			// The local network prefixes are passed to the iptables fallbacks.
			if len(testCase.localNetworks) > 0 && len(testCase.expectedCalls) > 0 {
				expectedPrefixes := make([]netip.Prefix, 0, len(testCase.localNetworks))
				for _, network := range testCase.localNetworks {
					expectedPrefixes = append(expectedPrefixes, network.IPNet)
				}
				assert.Equal(t, expectedPrefixes, impl.localPrefixes)
			}

			warnings := logger.entriesContaining("warn", "")
			if len(testCase.expectedWarnSubstr) == 0 {
				assert.Empty(t, warnings, "no warning should be logged")
			} else {
				require.Len(t, warnings, 1)
				for _, expected := range testCase.expectedWarnSubstr {
					assert.Contains(t, warnings[0], expected)
				}
			}

			// Every fallback is logged at debug level.
			fallbackDebugs := logger.entriesContaining("debug", "falling back to")
			assert.Len(t, fallbackDebugs, testCase.expectedFallbackDebugs)
		})
	}
}
