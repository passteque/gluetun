package updater

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

const testServersHTML = `
<table>
	<thead><tr><th>Country</th><th>City</th><th>Server</th><th>Protocols</th><th>Config</th></tr></thead>
	<tbody>
		<tr data-country="Ireland">
			<td><a href="/servers/country/Ireland">Ireland</a></td>
			<td>Dublin</td>
			<td>dub1.gpvpn.com</td>
			<td>OpenVPN, Cisco IPSec</td>
			<td><a href="/servers/filegen/dub1.gpvpn.com/o">OpenVPN</a></td>
		</tr>
		<tr data-country="United States">
			<td><a href="/servers/country/United States">United States</a></td>
			<td>Washington, DC</td>
			<td>iad1.gpvpn.com</td>
			<td>OpenVPN, Cisco IPSec</td>
			<td><a href="/servers/filegen/iad1.gpvpn.com/o">OpenVPN</a></td>
		</tr>
		<tr>
			<td>Nowhere</td>
			<td>Atlantis</td>
			<td>atl1.example.com</td>
			<td>OpenVPN</td>
		</tr>
		<tr>
			<td>Sweden</td>
			<td>Stockholm</td>
			<td>arn1.gpvpn.com</td>
			<td>Cisco IPSec</td>
		</tr>
	</tbody>
</table>`

func Test_parseHTML(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		html       string
		servers    []models.Server
		warnings   []string
		errMessage string
	}{
		"success": {
			html: testServersHTML,
			servers: []models.Server{
				{Country: "Ireland", City: "Dublin", Hostname: "dub1.gpvpn.com"},
				{Country: "United States", City: "Washington, DC", Hostname: "iad1.gpvpn.com"},
			},
			warnings: []string{"unexpected hostname atl1.example.com"},
		},
		"no_server": {
			html:       `<table><tr><td>a</td></tr></table>`,
			errMessage: "no server row found",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootNode, err := html.Parse(strings.NewReader(testCase.html))
			require.NoError(t, err)

			servers, warnings, err := parseHTML(rootNode)

			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errMessage)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, testCase.servers, servers)
			require.Len(t, warnings, len(testCase.warnings))
			for i, warning := range warnings {
				assert.Contains(t, warning, testCase.warnings[i])
			}
		})
	}
}

type warnerMock struct{ warnings []string }

func (w *warnerMock) Warn(message string) { w.warnings = append(w.warnings, message) }

func Test_fetchServers(t *testing.T) {
	t.Parallel()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("context_canceled", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, r.Context().Err()
		})}
		servers, err := fetchServers(canceledCtx, client, &warnerMock{})
		assert.Nil(t, servers)
		require.Error(t, err)
		assert.ErrorContains(t, err, `fetching HTML code: Get "https://ghostpath.com/servers": context canceled`)
	})

	t.Run("bad_status", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "Not Found", Body: http.NoBody}, nil
		})}
		_, err := fetchServers(context.Background(), client, &warnerMock{})
		assert.ErrorContains(t, err, "HTTP status code not OK: 404 Not Found")
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "https://ghostpath.com/servers", r.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(testServersHTML)),
			}, nil
		})}
		warner := &warnerMock{}
		servers, err := fetchServers(context.Background(), client, warner)
		require.NoError(t, err)
		assert.Equal(t, []models.Server{
			{Country: "Ireland", City: "Dublin", Hostname: "dub1.gpvpn.com"},
			{Country: "United States", City: "Washington, DC", Hostname: "iad1.gpvpn.com"},
		}, servers)
		assert.Len(t, warner.warnings, 1)
	})
}
