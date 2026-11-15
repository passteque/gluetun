package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/portforward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_PortForwardHandler_setPortForwarded(t *testing.T) {
	t.Parallel()

	const forwardedPort = uint16(45066)
	setPortsErr := errors.New("setting port forwarded at runtime is not supported " +
		"with internally running port forwarding code")
	warned := func(err error) string {
		return fmt.Sprintf("setting forwarded ports: %s", err)
	}

	testCases := map[string]struct {
		expectedStatus int
		expectedBody   string
		newHandler     func(t *testing.T) http.Handler
	}{
		"ports_set": {
			expectedStatus: http.StatusOK,
			expectedBody:   "",
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				portForward := NewMockPortForwarding(ctrl)
				portForward.EXPECT().
					SetPortsForwarded([]uint16{forwardedPort}).
					Return(nil)
				return &portForwardHandler{
					ctx: t.Context(), portForward: portForward, warner: logger,
				}
			},
		},
		// The run loop starts a service of its own, so asking for ports before
		// the first one exists is recoverable.
		"no_service_running_yet": {
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   warned(portforward.ErrServiceNotRunning),
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warn(warned(portforward.ErrServiceNotRunning))
				portForward := NewMockPortForwarding(ctrl)
				portForward.EXPECT().
					SetPortsForwarded([]uint16{forwardedPort}).
					Return(portforward.ErrServiceNotRunning)
				return &portForwardHandler{
					ctx: t.Context(), portForward: portForward, warner: logger,
				}
			},
		},
		"runtime_change_not_supported": {
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "failed setting forwarded ports",
			newHandler: func(t *testing.T) http.Handler {
				t.Helper()
				ctrl := gomock.NewController(t)
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Warn(warned(setPortsErr))
				portForward := NewMockPortForwarding(ctrl)
				portForward.EXPECT().
					SetPortsForwarded([]uint16{forwardedPort}).
					Return(setPortsErr)
				return &portForwardHandler{
					ctx: t.Context(), portForward: portForward, warner: logger,
				}
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := fmt.Sprintf(`{"ports":[%d]}`, forwardedPort)
			request, err := http.NewRequestWithContext(t.Context(),
				http.MethodPut, "/open port", strings.NewReader(body))
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler := testCase.newHandler(t)
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, testCase.expectedStatus, recorder.Code)
			assert.Equal(t, testCase.expectedBody, strings.TrimSpace(recorder.Body.String()))
		})
	}
}
