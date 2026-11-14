package api

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func Test_internetData_FetchInfo(t *testing.T) {
	t.Parallel()

	const ownIPURL = "https://api.internetdata.io/myip"

	testCases := map[string]struct {
		ip                 netip.Addr
		token              string
		expectedURL        string
		expectedAuthHeader string
		responseStatus     int
		responseBody       string
		result             models.PublicIP
		errWrapped         error
		errMessage         string
	}{
		"own_ip_without_token": {
			expectedURL:    ownIPURL,
			responseStatus: http.StatusOK,
			responseBody: `{"ip":"146.70.116.130","hostname":"","location":{"country":"AT",` +
				`"timezone":"Europe/Vienna"},"asn":{"asn":9009,"name":"M247 Europe SRL"}}`,
			result: models.PublicIP{
				IP:           netip.MustParseAddr("146.70.116.130"),
				Country:      "Austria",
				Organization: "AS9009 M247 Europe SRL",
				Timezone:     "Europe/Vienna",
			},
		},
		"ip_with_token": {
			ip:                 netip.MustParseAddr("8.8.8.8"),
			token:              "abc",
			expectedURL:        "https://api.internetdata.io/8.8.8.8",
			expectedAuthHeader: "Bearer abc",
			responseStatus:     http.StatusOK,
			responseBody: `{"ip":"8.8.8.8","hostname":"dns.google","location":{"country":"US",` +
				`"region":"California","city":"Mountain View","postal_code":"94043","latitude":37.4,` +
				`"longitude":-122.1,"timezone":"America/Los_Angeles"},"asn":{"asn":15169,"name":"Google LLC"}}`,
			result: models.PublicIP{
				IP:           netip.MustParseAddr("8.8.8.8"),
				Region:       "California",
				Country:      "United States",
				City:         "Mountain View",
				Hostname:     "dns.google",
				Location:     "37.400000,-122.100000",
				Organization: "AS15169 Google LLC",
				PostalCode:   "94043",
				Timezone:     "America/Los_Angeles",
			},
		},
		"invalid_token": {
			token:              "abc",
			expectedURL:        ownIPURL,
			expectedAuthHeader: "Bearer abc",
			responseStatus:     http.StatusUnauthorized,
			responseBody:       `{"error":"API key is not valid"}`,
			errMessage:         "token is not valid: 401 Unauthorized",
		},
		"too_many_requests": {
			expectedURL:    ownIPURL,
			responseStatus: http.StatusTooManyRequests,
			responseBody:   `{"error":"rate limited"}`,
			errWrapped:     ErrTooManyRequests,
			errMessage:     "too many requests sent for this month from " + ownIPURL + ": 429 429 Too Many Requests",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{
				Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					assert.Equal(t, testCase.expectedURL, request.URL.String())
					assert.Equal(t, testCase.expectedAuthHeader, request.Header.Get("Authorization"))
					return &http.Response{
						StatusCode: testCase.responseStatus,
						Status: strconv.Itoa(testCase.responseStatus) + " " +
							http.StatusText(testCase.responseStatus),
						Body: io.NopCloser(strings.NewReader(testCase.responseBody)),
					}, nil
				}),
			}
			fetcher := newInternetData(client, testCase.token)

			result, err := fetcher.FetchInfo(context.Background(), testCase.ip)

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.result, result)
		})
	}
}
