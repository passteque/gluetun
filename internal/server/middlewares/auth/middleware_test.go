package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_authHandler_ServeHTTP(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings      Settings
		makeLogger    func(ctrl *gomock.Controller) *MockDebugLogger
		requestMethod string
		requestPath   string
		statusCode    int
		responseBody  string
	}{
		"route_has_no_role": {
			settings: Settings{
				Roles: []Role{
					{Name: "role1", Auth: AuthNone, Routes: []string{"GET /a"}},
				},
			},
			makeLogger: func(ctrl *gomock.Controller) *MockDebugLogger {
				logger := NewMockDebugLogger(ctrl)
				logger.EXPECT().Debugf("url path %s is not a valid route", "/b")
				return logger
			},
			requestMethod: http.MethodGet,
			requestPath:   "/b",
			statusCode:    http.StatusNotFound,
			responseBody:  "Not Found\n",
		},
		"authorized_none": {
			settings: Settings{
				Roles: []Role{
					{Name: "role1", Auth: AuthNone, Routes: []string{"GET /v1/portforward"}},
				},
			},
			makeLogger: func(ctrl *gomock.Controller) *MockDebugLogger {
				logger := NewMockDebugLogger(ctrl)
				logger.EXPECT().Debugf("access to route %s authorized for role %s",
					"GET /v1/portforward", "role1")
				return logger
			},
			requestMethod: http.MethodGet,
			requestPath:   "/v1/portforward",
			statusCode:    http.StatusOK,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			var debugLogger DebugLogger
			if testCase.makeLogger != nil {
				debugLogger = testCase.makeLogger(ctrl)
			}
			middleware, err := New(testCase.settings, debugLogger)
			require.NoError(t, err)

			childHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := middleware(childHandler)

			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)

			client := server.Client()

			requestURL, err := url.JoinPath(server.URL, testCase.requestPath)
			require.NoError(t, err)
			request, err := http.NewRequestWithContext(context.Background(),
				testCase.requestMethod, requestURL, nil)
			require.NoError(t, err)

			response, err := client.Do(request)
			require.NoError(t, err)
			t.Cleanup(func() {
				err = response.Body.Close()
				assert.NoError(t, err)
			})

			assert.Equal(t, testCase.statusCode, response.StatusCode)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, testCase.responseBody, string(body))
		})
	}
}
