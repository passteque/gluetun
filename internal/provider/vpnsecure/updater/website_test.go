package updater

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/net/html"
)

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func Test_fetchServers(t *testing.T) {
	t.Parallel()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	testCases := map[string]struct {
		ctx            context.Context
		responseStatus int
		responseBody   io.ReadCloser
		servers        []models.Server
		errMessage     string
	}{
		"context_canceled": {
			ctx:        canceledCtx,
			errMessage: `fetching HTML code: Get "https://www.vpnsecure.me/locations/": context canceled`,
		},
		"success_with_testdata": {
			ctx:            context.Background(),
			responseStatus: http.StatusOK,
			responseBody: io.NopCloser(strings.NewReader(`
<body data-controller="menu" class="locations">
	<div id="servers" class="container mt-5 mt-lg-6">
		<div class="col-12 box dark-gray d-lg-none">
			<h3>
				<span class="flag">🇦🇺</span>
				Australia
			</h3>
			<div class="col-12 box white">
				<table>
					<thead>
						<tr>
							<th><div class="green-circle"></div></th>
							<th>City</th>
							<th class="right">AU #01</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td colspan="2">
								WireGuard
							</td>
						</tr>
						<tr>
							<td colspan="2">
								OpenVPN
							</td>
						</tr>
						<tr>
							<td colspan="2">
								Stealth Mode
							</td>
						</tr>
						<tr>
							<td colspan="2">
								Streaming
							</td>
						</tr>
						<tr>
							<td colspan="2">
								Dedicated IP
							</td>
						</tr>
						<tr>
							<td colspan="2">
								Fast (1Gbps)
							</td>
						</tr>
						<tr>
							<td colspan="2">
								Adblocker
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</div>
</body>
			`)),
			servers: []models.Server{
				{
					Country:  "Australia",
					City:     "City",
					Hostname: "au1.isponeder.com",
					Premium:  true,
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, http.MethodGet, r.Method)
					assert.Equal(t, r.URL.String(), "https://www.vpnsecure.me/locations/")

					ctxErr := r.Context().Err()
					if ctxErr != nil {
						return nil, ctxErr
					}

					return &http.Response{
						StatusCode: testCase.responseStatus,
						Status:     http.StatusText(testCase.responseStatus),
						Body:       testCase.responseBody,
					}, nil
				}),
			}

			warner := common.NewMockWarner(ctrl)

			servers, err := fetchServers(testCase.ctx, client, warner)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.servers, servers)
		})
	}
}

func Test_parseHTML(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rootNode   *html.Node
		servers    []models.Server
		warnings   []string
		errMessage string
	}{
		"empty_html": {
			rootNode:   parseTestHTML(t, ""),
			errMessage: `HTML servers container div not found: in HTML code: <html><head></head><body></body></html>`,
		},
		"missing_servers_div": {
			rootNode:   parseTestHTML(t, `<div id="other"></div>`),
			errMessage: "HTML servers container div not found",
		},
		"server_without_green_circle_is_skipped": {
			rootNode: parseTestHTML(t, `<div id="servers">
				<div class="box dark-gray">
					<h3>Germany</h3>
					<div class="box white">
						<table>
							<thead>
								<tr>
									<th><div class="red-circle"></div></th>
									<th>Berlin</th>
									<th class="right">DE #01</th>
								</tr>
							</thead>
						</table>
					</div>
				</div>
			</div>`),
			// servers is nil (all servers skipped)
			warnings: []string{"skipping server which is not up"},
		},
		"server_without_Dedicated_IP_is_not_premium": {
			rootNode: parseTestHTML(t, `<div id="servers">
				<div class="box dark-gray">
					<h3>Germany</h3>
					<div class="box white">
						<table>
							<thead>
								<tr>
									<th><div class="green-circle"></div></th>
									<th>Berlin</th>
									<th class="right">DE #01</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td colspan="2">Dedicated IP</td>
									<td class="right"><img src="/purple-cross.svg"></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>`),
			servers: []models.Server{
				{
					Country:  "Germany",
					City:     "Berlin",
					Hostname: "de1.isponeder.com",
					Premium:  false,
				},
			},
		},
		"server_with_Dedicated_IP_is_premium": {
			rootNode: parseTestHTML(t, `<div id="servers">
				<div class="box dark-gray">
					<h3>Germany</h3>
					<div class="box white">
						<table>
							<thead>
								<tr>
									<th><div class="green-circle"></div></th>
									<th>Berlin</th>
									<th class="right">DE #01</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td colspan="2">Dedicated IP</td>
									<td class="right"><img src="/pink-check.svg"></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>`),
			servers: []models.Server{
				{
					Country:  "Germany",
					City:     "Berlin",
					Hostname: "de1.isponeder.com",
					Premium:  true,
				},
			},
		},
		"country_with_flag_emoji_prefix_is_stripped": {
			rootNode: parseTestHTML(t, `<div id="servers">
				<div class="box dark-gray">
					<h3><span class="flag">🇩🇪</span> Germany</h3>
					<div class="box white">
						<table>
							<thead>
								<tr>
									<th><div class="green-circle"></div></th>
									<th>Berlin</th>
									<th class="right">DE #01</th>
								</tr>
							</thead>
							<tbody></tbody>
						</table>
					</div>
				</div>
			</div>`),
			servers: []models.Server{
				{
					Country:  "Germany",
					City:     "Berlin",
					Hostname: "de1.isponeder.com",
				},
			},
		},
		"country_name_starting_with_emoji_inline_text": {
			rootNode: parseTestHTML(t, `<div id="servers">
				<div class="box dark-gray">
					<h3>🇯🇵 Japan</h3>
					<div class="box white">
						<table>
							<thead>
								<tr>
									<th><div class="green-circle"></div></th>
									<th>Tokyo</th>
									<th class="right">JP #01</th>
								</tr>
							</thead>
							<tbody></tbody>
						</table>
					</div>
				</div>
			</div>`),
			servers: []models.Server{
				{
					Country:  "Japan",
					City:     "Tokyo",
					Hostname: "jp1.isponeder.com",
				},
			},
		},
		"test_data": {
			rootNode: parseTestDataIndexHTML(t),
			servers: []models.Server{
				{Country: "Australia", City: "Sydney", Hostname: "au1.isponeder.com", Premium: false},
				{Country: "Brazil", City: "São Paulo", Hostname: "br1.isponeder.com", Premium: false},
				{Country: "Canada", City: "Montréal", Hostname: "ca.isponeder.com", Premium: true},
				{Country: "Canada", City: "Montréal", Hostname: "ca1.isponeder.com", Premium: true},
				{Country: "Canada", City: "Montréal", Hostname: "ca2.isponeder.com", Premium: true},
				{Country: "Canada", City: "Montréal", Hostname: "ca3.isponeder.com", Premium: true},
				{Country: "Czech Republic", City: "Prague", Hostname: "cz1.isponeder.com", Premium: true},
				{Country: "France", City: "Roubaix", Hostname: "fr.isponeder.com", Premium: true},
				{Country: "France", City: "Roubaix", Hostname: "fr1.isponeder.com", Premium: true},
				{Country: "France", City: "Roubaix", Hostname: "fr2.isponeder.com", Premium: true},
				{Country: "France", City: "Strasbourg", Hostname: "fr3.isponeder.com", Premium: true},
				{Country: "France", City: "Strasbourg", Hostname: "fr4.isponeder.com", Premium: true},
				{Country: "Germany", City: "Frankfurt", Hostname: "de2.isponeder.com", Premium: true},
				{Country: "Germany", City: "Limburg", Hostname: "de1.isponeder.com", Premium: true},
				{Country: "Hong Kong", City: "Hong Kong", Hostname: "hk1.isponeder.com", Premium: false},
				{Country: "India", City: "Mumbai", Hostname: "in1.isponeder.com", Premium: false},
				{Country: "Ireland", City: "Dublin", Hostname: "ie1.isponeder.com", Premium: true},
				{Country: "Ireland", City: "Dublin", Hostname: "ie2.isponeder.com", Premium: true},
				{Country: "Ireland", City: "Dublin", Hostname: "ie3.isponeder.com", Premium: true},
				{Country: "Israel", City: "Tel Aviv", Hostname: "il1.isponeder.com", Premium: false},
				{Country: "Italy", City: "Milan", Hostname: "it1.isponeder.com", Premium: true},
				{Country: "Italy", City: "Milan", Hostname: "it2.isponeder.com", Premium: true},
				{Country: "Japan", City: "Tokyo", Hostname: "jp1.isponeder.com", Premium: false},
				{Country: "Lithuania", City: "Vilnius", Hostname: "lt1.isponeder.com", Premium: true},
				{Country: "Mexico", City: "Mexico City", Hostname: "mx1.isponeder.com", Premium: false},
				{Country: "Netherlands", City: "Amsterdam", Hostname: "nl1.isponeder.com", Premium: true},
				{Country: "Netherlands", City: "Amsterdam", Hostname: "nl2.isponeder.com", Premium: true},
				{Country: "Poland", City: "Warsaw", Hostname: "pl1.isponeder.com", Premium: true},
				{Country: "Romania", City: "Bucharest", Hostname: "ro2.isponeder.com", Premium: true},
				{Country: "Romania", City: "Voluntari", Hostname: "ro1.isponeder.com", Premium: true},
				{Country: "Russia", City: "Saint Petersburg", Hostname: "ru1.isponeder.com", Premium: false},
				{Country: "Singapore", City: "Singapore", Hostname: "sg.isponeder.com", Premium: true},
				{Country: "Singapore", City: "Singapore", Hostname: "sg1.isponeder.com", Premium: true},
				{Country: "Spain", City: "Madrid", Hostname: "es1.isponeder.com", Premium: true},
				{Country: "Spain", City: "Madrid", Hostname: "es2.isponeder.com", Premium: true},
				{Country: "Sweden", City: "Stockholm", Hostname: "se1.isponeder.com", Premium: false},
				{Country: "Switzerland", City: "Zurich", Hostname: "ch1.isponeder.com", Premium: false},
				{Country: "Ukraine", City: "Kyiv", Hostname: "ua1.isponeder.com", Premium: true},
				{Country: "Ukraine", City: "Kyiv", Hostname: "ua2.isponeder.com", Premium: true},
				{Country: "United Kingdom", City: "Bexleyheath", Hostname: "gb3.isponeder.com", Premium: false},
				{Country: "United Kingdom", City: "Erith", Hostname: "gb2.isponeder.com", Premium: false},
				{Country: "United Kingdom", City: "London", Hostname: "gb1.isponeder.com", Premium: false},
				{Country: "United States", City: "Missouri", Hostname: "us5.isponeder.com", Premium: false},
				{Country: "United States", City: "New York", Hostname: "us1.isponeder.com", Premium: false},
				{Country: "United States", City: "New York", Hostname: "us4.isponeder.com", Premium: false},
				{Country: "United States", City: "Oregon", Hostname: "us6.isponeder.com", Premium: true},
				{Country: "United States", City: "Oregon", Hostname: "us7.isponeder.com", Premium: true},
				{Country: "United States", City: "Oregon", Hostname: "us8.isponeder.com", Premium: true},
				{Country: "United States", City: "Oregon", Hostname: "us9.isponeder.com", Premium: true},
				{Country: "United States", City: "Oregon", Hostname: "us10.isponeder.com", Premium: true},
				{Country: "United States", City: "Texas", Hostname: "us2.isponeder.com", Premium: false},
				{Country: "United States", City: "Texas", Hostname: "us3.isponeder.com", Premium: false},
				{Country: "United States", City: "Virginia", Hostname: "us11.isponeder.com", Premium: true},
				{Country: "United States", City: "Virginia", Hostname: "us12.isponeder.com", Premium: true},
				{Country: "United States", City: "Virginia", Hostname: "us13.isponeder.com", Premium: true},
				{Country: "United States", City: "Virginia", Hostname: "us14.isponeder.com", Premium: true},
				{Country: "United States", City: "Virginia", Hostname: "us15.isponeder.com", Premium: true},
				{Country: "United States", City: "Virginia", Hostname: "us16.isponeder.com", Premium: true},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			servers, warnings, err := parseHTML(testCase.rootNode)

			assert.Equal(t, testCase.servers, servers)
			for _, expected := range testCase.warnings {
				found := false
				for _, actual := range warnings {
					if strings.Contains(actual, expected) {
						found = true
						break
					}
				}
				assert.True(t, found, "warning %q not found in %v", expected, warnings)
			}
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
