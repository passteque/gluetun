package httpserver

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

//go:generate mockgen -destination=logger_mock_test.go -package $GOPACKAGE . Logger

func Test_New(t *testing.T) {
	t.Parallel()

	someHandler := http.NewServeMux()
	someLogger := &testLogger{}

	testCases := map[string]struct {
		settings   Settings
		expected   *Server
		errMessage string
	}{
		"empty settings": {
			errMessage: "http server settings validation failed: HTTP handler cannot be left unset",
		},
		"filled settings": {
			settings: Settings{
				Address:           ":8001",
				Handler:           someHandler,
				Logger:            someLogger,
				ReadHeaderTimeout: time.Second,
				ReadTimeout:       time.Second,
				ShutdownTimeout:   time.Second,
			},
			expected: &Server{
				address:           ":8001",
				handler:           someHandler,
				logger:            someLogger,
				readHeaderTimeout: time.Second,
				readTimeout:       time.Second,
				shutdownTimeout:   time.Second,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server, err := New(testCase.settings)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			if server != nil {
				assert.NotNil(t, server.addressSet)
				server.addressSet = nil
			}

			assert.Equal(t, testCase.expected, server)
		})
	}
}
