package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Handlers_reject_unknown_request_body_fields(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		path         string
		body         string
		expectedBody string
		newHandler   func(t *testing.T) http.Handler
	}{
		"vpn_status": {
			path:         "/vpn/status",
			body:         `{"status":"running","unexpected":true}`,
			expectedBody: `json: unknown field "unexpected"`,
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				return &vpnHandler{ctx: t.Context(), looper: NewMockVPNLooper(ctrl), warner: logger}
			},
		},
		"openvpn_status": {
			path:         "/openvpn/status",
			body:         `{"status":"running","unexpected":true}`,
			expectedBody: `json: unknown field "unexpected"`,
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				return &openvpnHandler{ctx: t.Context(), looper: NewMockVPNLooper(ctrl), warner: logger}
			},
		},
		"dns_status": {
			path:         "/dns/status",
			body:         `{"status":"running","unexpected":true}`,
			expectedBody: `json: unknown field "unexpected"`,
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				return &dnsHandler{ctx: t.Context(), loop: NewMockDNSLoop(ctrl), warner: logger}
			},
		},
		"updater_status": {
			path:         "/updater/status",
			body:         `{"status":"running","unexpected":true}`,
			expectedBody: `json: unknown field "unexpected"`,
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				return &updaterHandler{ctx: t.Context(), looper: NewMockUpdaterLooper(ctrl), warner: logger}
			},
		},
		"portforward": {
			path:         "/portforward",
			body:         `{"ports":[1234],"unexpected":true}`,
			expectedBody: "failed setting forwarded ports",
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warn(`failed setting forwarded ports: json: unknown field "unexpected"`).Times(1)
				return &portForwardHandler{ctx: t.Context(), portForward: NewMockPortForwarding(ctrl), warner: logger}
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// No backend mock expectations are configured, so any backend call fails the test.
			handler := testCase.newHandler(t)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPut,
				testCase.path, strings.NewReader(testCase.body))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			require.Equal(t, http.StatusBadRequest, response.Code)
			assert.Contains(t, response.Body.String(), testCase.expectedBody)
		})
	}
}
