package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_detectResolvers_live answers with the real ipleak.net service.
func Test_detectResolvers_live(t *testing.T) {
	t.Parallel()

	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	client := http.DefaultClient
	resolvers, err := detectResolvers(ctx, client)
	require.NoError(t, err)
	require.NotEmpty(t, resolvers)
}

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func Test_detectResolvers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		// ip is the "ip" field of every answered response.
		ip string
		// transportError makes every request fail instead of answering.
		transportError bool
		resolvers      []netip.Addr
		errContains    string
	}{
		"single_resolver": {
			ip:        `{"1.2.3.4":2}`,
			resolvers: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		"multiple_resolvers": {
			ip:        `{"5.6.7.8":1,"1.2.3.4":2}`,
			resolvers: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
		},
		"sorted_numerically": {
			ip: `{"10.0.0.2":1,"9.0.0.1":1,"2.2.2.2":1}`,
			resolvers: []netip.Addr{
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("9.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
			},
		},
		"ipv4_before_ipv6": {
			ip: `{"2606:4700:4700::1111":1,"1.2.3.4":1}`,
			resolvers: []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("2606:4700:4700::1111"),
			},
		},
		"no_resolver_detected": {
			ip:          `[]`,
			errContains: "no DNS resolver detected",
		},
		"invalid_resolver_address": {
			ip:          `{"not-an-address":1}`,
			errContains: "parsing resolver address not-an-address",
		},
		"request_failed": {
			transportError: true,
			errContains:    "request failed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int64
			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					requests.Add(1)
					if testCase.transportError {
						return nil, errors.New("stubbed transport failure")
					}
					session, _, _ := strings.Cut(r.URL.Host, "-")
					body := fmt.Sprintf(`{"session":%q,"ip":%s}`, session, testCase.ip)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				}),
			}

			resolvers, err := detectResolvers(t.Context(), client)

			if testCase.errContains != "" {
				assert.ErrorContains(t, err, testCase.errContains)
				assert.Nil(t, resolvers)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int64(5), requests.Load())
			assert.Equal(t, testCase.resolvers, resolvers)
		})
	}
}

func Test_ipLeakData_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		data   string
		parsed ipLeakData
		// errValue is the expected json.UnmarshalTypeError.Value, set when
		// the input data is expected to fail decoding.
		errValue string
	}{
		"detected_resolvers": {
			data: `{"session":"abc","ip":{"1.2.3.4":2,"5.6.7.8":1}}`,
			parsed: ipLeakData{
				Session: "abc",
				IP:      dnsCounters{"1.2.3.4": 2, "5.6.7.8": 1},
			},
		},
		"empty_object": {
			data:   `{"session":"abc","ip":{}}`,
			parsed: ipLeakData{Session: "abc", IP: dnsCounters{}},
		},
		"empty_array": {
			data:   `{"session":"abc","ip":[]}`,
			parsed: ipLeakData{Session: "abc", IP: dnsCounters{}},
		},
		"non_empty_array": {
			data:     `{"session":"abc","ip":["1.2.3.4"]}`,
			errValue: "array",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var parsed ipLeakData
			err := json.Unmarshal([]byte(testCase.data), &parsed)

			if testCase.errValue != "" {
				var typeErr *json.UnmarshalTypeError
				require.ErrorAs(t, err, &typeErr)
				assert.Equal(t, testCase.errValue, typeErr.Value)
				assert.Equal(t, reflect.TypeFor[map[string]uint](), typeErr.Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.parsed, parsed)
		})
	}
}

// testLogger is a test double for the [Logger] interface that records the entries.
type testLogger struct {
	mu      sync.Mutex
	entries []string // "level: message"
}

func (l *testLogger) add(level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, level+": "+message)
}

func (l *testLogger) Debug(s string)           { l.add("debug", s) }
func (l *testLogger) Info(s string)            { l.add("info", s) }
func (l *testLogger) Infof(f string, a ...any) { l.add("info", fmt.Sprintf(f, a...)) }
func (l *testLogger) Warn(s string)            { l.add("warn", s) }
func (l *testLogger) Warnf(f string, a ...any) { l.add("warn", fmt.Sprintf(f, a...)) }
func (l *testLogger) Error(s string)           { l.add("error", s) }

func (l *testLogger) loggedEntries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.entries)
}

func Test_Loop_checkResolvers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		checkEnabled bool
		// ip is the "ip" field of every answered response.
		ip               string
		expectedRequests int64
		// expectedLogs is empty when nothing should be logged.
		expectedLogs []string
	}{
		"check_disabled": {
			checkEnabled: false,
			ip:           `{"1.2.3.4":1}`,
		},
		"check_enabled_resolvers_detected": {
			checkEnabled:     true,
			ip:               `{"5.6.7.8":1,"1.2.3.4":1}`,
			expectedRequests: 5,
			expectedLogs: []string{
				"info: DNS resolvers detected through the tunnel: [1.2.3.4 5.6.7.8]",
			},
		},
		"check_enabled_no_resolver_detected": {
			checkEnabled:     true,
			ip:               `[]`,
			expectedRequests: 5,
			expectedLogs: []string{
				"warn: detecting DNS resolvers through the tunnel: no DNS resolver detected",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int64
			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					requests.Add(1)
					session, _, _ := strings.Cut(r.URL.Host, "-")
					body := fmt.Sprintf(`{"session":%q,"ip":%s}`, session, testCase.ip)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				}),
			}
			logger := new(testLogger)
			loop := &Loop{client: client, logger: logger}

			loop.checkResolvers(t.Context(), testCase.checkEnabled)

			assert.Equal(t, testCase.expectedRequests, requests.Load())
			assert.Equal(t, testCase.expectedLogs, logger.loggedEntries())
		})
	}
}
