package updater

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
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
		"context canceled": {
			ctx:        canceledCtx,
			errMessage: `fetching HTML code: Get "https://www.vpnsecure.me/vpn-locations/": context canceled`,
		},
		"success": {
			ctx:            context.Background(),
			responseStatus: http.StatusOK,
			responseBody: io.NopCloser(strings.NewReader(`
			<div class="blk blk--white locations-list">
				<div class="blk__i">
					<div>
					<a href="https://www.vpnsecure.me/vpn-locations/australia/">
						<h4>Australia</h4>
					</a>
					<div class="grid grid--3 grid--locations">
						<dl class="grid__i">
							<dt>
								au1
								<span class="status status--up">up</span>
							</dt>
							<dd>
								<div><span>City:</span> <strong>City</strong></div>
								<div><span>Region:</span> <strong>Region</strong></div>
								<div><span>Premium:</span> <strong>YES</strong></div>

							</dd>
						</dl>
					</div>
				</div>
			</div>
			`)),
			servers: []models.Server{
				{
					Country:  "Australia",
					City:     "City",
					Region:   "Region",
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
					assert.Equal(t, r.URL.String(), "https://www.vpnsecure.me/vpn-locations/")

					ctxErr := r.Context().Err()
					if ctxErr != nil {
						return nil, ctxErr
					}

					return &http.Response{
						StatusCode: http.StatusOK,
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
		"empty html": {
			rootNode:   parseTestHTML(t, ""),
			errMessage: `HTML servers container div not found: in HTML code: <html><head></head><body></body></html>`,
		},
		"test data": {
			rootNode: parseTestDataIndexHTML(t),
			warnings: []string{
				"no grid item found: in HTML code: <div class=\"grid grid--3 grid--locations\">\n                      </div>",
			},
			//nolint:lll
			servers: []models.Server{
				{Country: "Australia", Region: "Queensland", City: "Brisbane", Hostname: "au1.isponeder.com", Premium: true},
				{Country: "Australia", Region: "New South Wales", City: "Sydney", Hostname: "au2.isponeder.com"},
				{Country: "Australia", Region: "New South Wales", City: "Sydney", Hostname: "au3.isponeder.com"},
				{Country: "Australia", Region: "New South Wales", City: "Sydney", Hostname: "au4.isponeder.com", Premium: true},
				{Country: "Austria", Region: "Vienna", City: "Vienna", Hostname: "at1.isponeder.com", Premium: true},
				{Country: "Austria", Region: "Vienna", City: "Vienna", Hostname: "at2.isponeder.com"},
				{Country: "Brazil", Region: "Sao Paulo", City: "Sao Paulo", Hostname: "br1.isponeder.com", Premium: true},
				{Country: "Belgium", Region: "Flanders", City: "Zaventem", Hostname: "be1.isponeder.com"},
				{Country: "Belgium", Region: "Brussels Hoofdstedelijk Gewest", City: "Brussel", Hostname: "be2.isponeder.com"},
				{Country: "Canada", Region: "Ontario", City: "Richmond Hill", Hostname: "ca1.isponeder.com"},
				{Country: "Canada", Region: "Ontario", City: "Richmond Hill", Hostname: "ca2.isponeder.com"},
				{Country: "Canada", Region: "Quebec", City: "Montréal", Hostname: "ca3.isponeder.com", Premium: true},
				{Country: "Denmark", Region: "Capital Region", City: "Copenhagen", Hostname: "dk1.isponeder.com", Premium: true},
				{Country: "Denmark", Region: "Capital Region", City: "Copenhagen", Hostname: "dk2.isponeder.com", Premium: true},
				{Country: "Denmark", Region: "Capital Region", City: "Ballerup", Hostname: "dk3.isponeder.com"},
				{Country: "France", Region: "Île-de-France", City: "Paris", Hostname: "fr1.isponeder.com"},
				{Country: "France", Region: "Île-de-France", City: "Paris", Hostname: "fr2.isponeder.com"},
				{Country: "France", Region: "Grand Est", City: "Strasbourg", Hostname: "fr3.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Frankfurt am Main", Hostname: "de1.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Frankfurt am Main", Hostname: "de2.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Frankfurt am Main", Hostname: "de3.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Frankfurt am Main", Hostname: "de4.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Limburg an der Lahn", Hostname: "de5.isponeder.com"},
				{Country: "Germany", Region: "Hesse", City: "Frankfurt am Main", Hostname: "de6.isponeder.com"},
				{Country: "Hungary", Region: "Budapest", City: "Budapest", Hostname: "hu1.isponeder.com", Premium: true},
				{Country: "India", Region: "Karnataka", City: "Doddaballapura", Hostname: "in1.isponeder.com"},
				{Country: "Indonesia", Region: "Special Capital Region of Jakarta", City: "Jakarta", Hostname: "id1.isponeder.com"},
				{Country: "Ireland", Region: "Dublin City", City: "Dublin", Hostname: "ie1.isponeder.com"},
				{Country: "Israel", Region: "Tel Aviv", City: "Tel Aviv", Hostname: "il1.isponeder.com", Premium: true},
				{Country: "Italy", Region: "Lombardy", City: "Milan", Hostname: "it1.isponeder.com", Premium: true},
				{Country: "Japan", Region: "Tokyo", City: "Tokyo", Hostname: "jp2.isponeder.com", Premium: true},
				{Country: "Mexico", Region: "México", City: "Ampliación San Mateo (Colonia Solidaridad)", Hostname: "mx1.isponeder.com"},
				{Country: "Netherlands", Region: "North Holland", City: "Haarlem", Hostname: "nl1.isponeder.com"},
				{Country: "Netherlands", Region: "South Holland", City: "Naaldwijk", Hostname: "nl2.isponeder.com"},
				{Country: "New Zealand", Region: "Auckland", City: "Auckland", Hostname: "nz1.isponeder.com"},
				{Country: "Norway", Region: "Oslo", City: "Oslo", Hostname: "no1.isponeder.com", Premium: true},
				{Country: "Norway", Region: "Stockholm", City: "Stockholm", Hostname: "no2.isponeder.com", Premium: true},
				{Country: "Poland", Region: "Mazovia", City: "Warsaw", Hostname: "pl1.isponeder.com", Premium: true},
				{Country: "Romania", Region: "Bucure?ti", City: "Bucharest", Hostname: "ro1.isponeder.com", Premium: true},
				{Country: "Russia", Region: "Moscow", City: "Moscow", Hostname: "ru1.isponeder.com", Premium: true},
				{Country: "Singapore", Region: "Singapore", City: "Singapore", Hostname: "sg1.isponeder.com", Premium: true},
				{Country: "South Africa", Region: "Western Cape", City: "Cape Town", Hostname: "za1.isponeder.com", Premium: true},
				{Country: "Spain", Region: "Madrid", City: "Madrid", Hostname: "es2.isponeder.com"},
				{Country: "Spain", Region: "Valencia", City: "Valencia", Hostname: "se1.isponeder.com"},
				{Country: "Sweden", Region: "Stockholm", City: "Stockholm", Hostname: "se2.isponeder.com", Premium: true},
				{Country: "Sweden", Region: "Stockholm", City: "Stockholm", Hostname: "se3.isponeder.com"},
				{Country: "Switzerland", Region: "Vaud", City: "Lausanne", Hostname: "ch1.isponeder.com"},
				{Country: "Switzerland", Region: "Geneva", City: "Geneva", Hostname: "ch1.isponeder.com", Premium: true},
				{Country: "Switzerland", Region: "Geneva", City: "Genève", Hostname: "ch2.isponeder.com", Premium: true},
				{Country: "Ukraine", Region: "Poltavs'ka Oblast'", City: "Kremenchuk", Hostname: "ua1.isponeder.com", Premium: true},
				{Country: "United Arab Emirates", Region: "Maharashtra", City: "Mumbai", Hostname: "ae1.isponeder.com", Premium: true},
				{Country: "United Kingdom", Region: "England", City: "London", Hostname: "uk2.isponeder.com"},
				{Country: "United Kingdom", Region: "England", City: "Kent", Hostname: "uk3.isponeder.com"},
				{Country: "United Kingdom", Region: "England", City: "London", Hostname: "uk4.isponeder.com"},
				{Country: "United Kingdom", Region: "England", City: "London", Hostname: "uk5.isponeder.com"},
				{Country: "United Kingdom", Region: "Brent", City: "Harlesden", Hostname: "uk6.isponeder.com"},
				{Country: "United Kingdom", Region: "England", City: "Manchester", Hostname: "uk7.isponeder.com"},
				{Country: "United States", Region: "New Jersey", City: "Secaucus", Hostname: "us1.isponeder.com"},
				{Country: "United States", Region: "New York", City: "New York City", Hostname: "us10.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us11.isponeder.com"},
				{Country: "United States", Region: "Illinois", City: "Chicago", Hostname: "us12.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us13.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us14.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us15.isponeder.com"},
				{Country: "United States", Region: "Illinois", City: "Chicago", Hostname: "us16.isponeder.com"},
				{Country: "United States", Region: "New York", City: "New York City", Hostname: "us2.isponeder.com"},
				{Country: "United States", Region: "Oregon", City: "Portland", Hostname: "us3.isponeder.com", Premium: true},
				{Country: "United States", Region: "Illinois", City: "Chicago", Hostname: "us4.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us5.isponeder.com"},
				{Country: "United States", Region: "California", City: "Los Angeles", Hostname: "us6.isponeder.com"},
				{Country: "United States", Region: "Illinois", City: "Chicago", Hostname: "us7.isponeder.com"},
				{Country: "United States", Region: "Georgia", City: "Atlanta", Hostname: "us8.isponeder.com"},
				{Country: "United States", Region: "Georgia", City: "Atlanta", Hostname: "us9.isponeder.com"},
				{Country: "Hong Kong", Region: "Central and Western", City: "Hong Kong", Hostname: "hk1.isponeder.com"},
				{Country: "United States West", Region: "California", City: "Los Angeles", Hostname: "us3.isponeder.com", Premium: true},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			servers, warnings, err := parseHTML(testCase.rootNode)

			assert.Equal(t, testCase.servers, servers)
			assert.Equal(t, testCase.warnings, warnings)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
