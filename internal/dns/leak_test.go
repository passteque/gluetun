package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_leakCheck(t *testing.T) {
	t.Parallel()

	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	client := http.DefaultClient
	report, err := leakCheck(ctx, client)
	require.NoError(t, err)
	require.NotEmpty(t, report)
}

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func Test_leakCheck_noResolver(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ip     string // "ip" field of every response
		report string
		errIs  error
	}{
		"resolvers_detected": {
			ip:     `{"1.2.3.4":2,"5.6.7.8":1}`,
			report: "1.2.3.4 (67%), 5.6.7.8 (34%)",
		},
		"no_resolver_detected": {
			ip:    `[]`,
			errIs: ErrNoResolverDetected,
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

			report, err := leakCheck(t.Context(), client)

			assert.Equal(t, int64(5), requests.Load())
			assert.ErrorIs(t, err, testCase.errIs)
			assert.Equal(t, testCase.report, report)
		})
	}
}

func Test_ipLeakData_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		data   string
		parsed ipLeakData
		errMsg string
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
			data:   `{"session":"abc","ip":["1.2.3.4"]}`,
			errMsg: "json: cannot unmarshal array into Go struct field ipLeakData.ip of type map[string]uint",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var parsed ipLeakData
			err := json.Unmarshal([]byte(testCase.data), &parsed)

			if testCase.errMsg != "" {
				require.EqualError(t, err, testCase.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.parsed, parsed)
		})
	}
}
