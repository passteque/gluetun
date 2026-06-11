package updater

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func Test_fechAPIServers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ctx            context.Context
		protocol       string
		requestBody    string
		responseStatus int
		responseBody   io.ReadCloser
		transportErr   error
		servers        []apiServer
		errMessage     string
	}{
		"transport_error": {
			ctx:            context.Background(),
			protocol:       "tcp",
			requestBody:    "action=vpn_servers&protocol=tcp",
			responseStatus: http.StatusOK,
			transportErr:   errors.New("test error"),
			errMessage: `sending request: Post ` +
				`"https://support.fastestvpn.com/wp-admin/admin-ajax.php": ` +
				`test error`,
		},
		"not_found_status_code": {
			ctx:            context.Background(),
			protocol:       "tcp",
			requestBody:    "action=vpn_servers&protocol=tcp",
			responseStatus: http.StatusNotFound,
			errMessage:     "HTTP status code not OK: 404",
		},
		"empty_data": {
			ctx:            context.Background(),
			protocol:       "tcp",
			requestBody:    "action=vpn_servers&protocol=tcp",
			responseStatus: http.StatusOK,
			responseBody:   io.NopCloser(strings.NewReader("")),
			servers:        []apiServer{},
		},
		"single_server": {
			ctx:            context.Background(),
			protocol:       "tcp",
			requestBody:    "action=vpn_servers&protocol=tcp",
			responseStatus: http.StatusOK,
			responseBody: io.NopCloser(strings.NewReader(
				"irrelevant<tr><td>Australia</td><td>Sydney</td>" +
					"<td>au-stream.jumptoserver.com</td></tr>irrelevant")),
			servers: []apiServer{
				{country: "Australia", city: "Sydney", hostname: "au-stream.jumptoserver.com"},
			},
		},
		"two_servers": {
			ctx:            context.Background(),
			protocol:       "tcp",
			requestBody:    "action=vpn_servers&protocol=tcp",
			responseStatus: http.StatusOK,
			responseBody: io.NopCloser(strings.NewReader(
				"<tr><td>Australia</td><td>Sydney</td><td>au-stream.jumptoserver.com</td></tr>" +
					"<tr><td>Australia</td><td>Sydney</td><td>au-01.jumptoserver.com</td></tr>")),
			servers: []apiServer{
				{country: "Australia", city: "Sydney", hostname: "au-stream.jumptoserver.com"},
				{country: "Australia", city: "Sydney", hostname: "au-01.jumptoserver.com"},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, apiURL, r.URL.String())
					requestBody, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					assert.Equal(t, testCase.requestBody, string(requestBody))
					if testCase.transportErr != nil {
						return nil, testCase.transportErr
					}
					return &http.Response{
						StatusCode: testCase.responseStatus,
						Body:       testCase.responseBody,
					}, nil
				}),
			}

			entries, err := fetchAPIServers(testCase.ctx, client, testCase.protocol)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.servers, entries)
		})
	}
}

func Test_getNextBlock(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		data       string
		startToken string
		endToken   string
		nextBlock  []byte
	}{
		"empty_data": {
			startToken: "<a>",
			endToken:   "</a>",
		},
		"start_token_not_found": {
			data:       "test</a>",
			startToken: "<a>",
			endToken:   "</a>",
		},
		"end_token_not_found": {
			data:       "<a>test",
			startToken: "<a>",
			endToken:   "</a>",
		},
		"block_found": {
			data:       "xy<a>test</a><a>test2</a>zx",
			startToken: "<a>",
			endToken:   "</a>",
			nextBlock:  []byte("<a>test</a>"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nextBlock := getNextBlock([]byte(testCase.data), testCase.startToken, testCase.endToken)

			assert.Equal(t, testCase.nextBlock, nextBlock)
		})
	}
}
