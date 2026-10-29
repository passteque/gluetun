package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_Updater_withLocations(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		servers    []models.Server
		minServers int
		warnings   []string
		kept       []models.Server
		errWrapped error
		errMessage string
	}{
		"known_country_and_city_from_hostname": {
			servers: []models.Server{{
				Hostname: "usny2-udp.ptoserver.com",
			}},
			kept: []models.Server{{
				Hostname: "usny2-udp.ptoserver.com",
				Country:  "United States",
				City:     "New York",
				Region:   "New York",
			}},
		},
		"inventory_city_kept_when_hostname_has_no_city": {
			servers: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				City:     "Somewhere",
			}},
			kept: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				Country:  "United States",
				City:     "Somewhere",
			}},
		},
		"unknown_country_with_inventory_city_dropped": {
			servers: []models.Server{{
				Hostname: "zz2-udp.ptoserver.com",
				City:     "Somewhere",
			}},
			warnings: []string{
				`unknown country code "zz" in hostname "zz2-udp.ptoserver.com"`,
			},
			kept: []models.Server{},
		},
		"not_enough_servers_after_dropping": {
			servers: []models.Server{
				{Hostname: "usny2-udp.ptoserver.com"},
				{
					Hostname: "zz2-udp.ptoserver.com",
					City:     "Somewhere",
				},
			},
			minServers: 2,
			warnings: []string{
				`unknown country code "zz" in hostname "zz2-udp.ptoserver.com"`,
			},
			errWrapped: common.ErrNotEnoughServers,
			errMessage: "not enough servers found: 1 and expected at least 2",
		},
		"exactly_min_servers": {
			servers: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
			}},
			minServers: 1,
			kept: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				Country:  "United States",
			}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			warner := common.NewMockWarner(ctrl)
			for _, warning := range testCase.warnings {
				warner.EXPECT().Warn(warning).Times(1)
			}

			updater := &Updater{logger: warner}

			kept, err := updater.withLocations(testCase.servers, testCase.minServers)

			assert.Equal(t, testCase.kept, kept)
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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
			errMessage: "file not found in the application archive",
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
					`"BASE_URL_BPC", "https://bpc-prod-a230.s3.serverwild.com"; "/{resellerUid}/inventory/shared/linux/v3/app.json"`),
				"node_modules/atom-sdk/node_modules/inventory/lib/offline-data/inventory-data.js": []byte(
					`{"Uid":"res_test"}`),
			}), ".gz")
			contentByPath := map[string][]byte{
				"/download/linux-vpn": []byte(`<a href="https://dhnx3d2u57yhc.cloudfront.net/purevpn.deb">Download</a>`),
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

			if testCase.err != nil {
				assert.ErrorIs(t, err, testCase.err)
			}
			assert.ErrorContains(t, err, testCase.errMessage)
			assert.Equal(t, clientTimeout, client.Timeout)
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
