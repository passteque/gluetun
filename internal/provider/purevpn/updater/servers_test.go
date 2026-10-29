package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_FetchServers_downloadTimeout(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		slowPath       string
		cancelDownload bool
		parentTimeout  time.Duration
		err            error
		errMessage     string
	}{
		"slow_deb_body": {
			slowPath:   "/purevpn.deb",
			err:        errFileNotFound,
			errMessage: "parsing app-bundled local data",
		},
		"download_page_timeout_unchanged": {
			slowPath:   "/download/linux-vpn",
			err:        context.DeadlineExceeded,
			errMessage: "fetching .deb URL",
		},
		"inventory_timeout_unchanged": {
			slowPath:   "/res_test/inventory/shared/linux/v3/app.json",
			err:        context.DeadlineExceeded,
			errMessage: "parsing inventory JSON",
		},
		"canceled_deb_body": {
			slowPath:       "/purevpn.deb",
			cancelDownload: true,
			err:            context.Canceled,
			errMessage:     "PureVPN .deb file",
		},
		"caller_deadline_during_deb_body": {
			slowPath:      "/purevpn.deb",
			parentTimeout: 750 * time.Millisecond,
			err:           context.DeadlineExceeded,
			errMessage:    "extracting files from PureVPN .deb file",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if testCase.parentTimeout != 0 {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, testCase.parentTimeout)
				defer deadlineCancel()
			}

			debContent := newDebArchive(t, newASARArchive(t, map[string][]byte{
				"node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js": []byte(
					`"BASE_URL_BPC", "https://example.com"; "/{resellerUid}/inventory/shared/linux/v3/app.json"`),
				"node_modules/atom-sdk/node_modules/inventory/lib/offline-data/inventory-data.js": []byte(
					`{"Uid":"res_test"}`),
			}), ".gz")
			contentByPath := map[string][]byte{
				"/download/linux-vpn": []byte(`<a href="https://example.com/purevpn.deb">Download</a>`),
				"/purevpn.deb":        debContent,
				"/res_test/inventory/shared/linux/v3/app.json": []byte(`{"body":{"countries":[{}]}}`),
			}
			const clientTimeout = 500 * time.Millisecond
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				content := contentByPath[request.URL.Path]
				if request.URL.Path == testCase.slowPath {
					_, _ = writer.Write(content[:1])
					assert.NoError(t, http.NewResponseController(writer).Flush())
					if testCase.cancelDownload {
						cancel()
					}
					timer := time.NewTimer(2 * clientTimeout)
					defer timer.Stop()
					select {
					case <-request.Context().Done():
						return
					case <-timer.C:
					}
					content = content[1:]
				}
				_, _ = writer.Write(content)
			}))
			defer server.Close()

			client := server.Client()
			transport := client.Transport
			client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				request = request.Clone(request.Context())
				request.URL.Host = server.Listener.Addr().String()
				return transport.RoundTrip(request)
			})
			client.Timeout = clientTimeout
			updater := New(client, nil, nil, nil)

			_, err := updater.FetchServers(ctx, 1)

			assert.ErrorIs(t, err, testCase.err)
			assert.ErrorContains(t, err, testCase.errMessage)
			assert.Equal(t, clientTimeout, client.Timeout)
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
