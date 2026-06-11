package pprof

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/httpserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:generate mockgen -destination=logger_mock_test.go -package $GOPACKAGE github.com/qdm12/gluetun/internal/httpserver Logger

func Test_Server(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	const address = "127.0.0.1:0"
	logger := NewMockLogger(ctrl)

	logger.EXPECT().Info(newRegexMatcher("^http server listening on 127.0.0.1:[1-9][0-9]{0,4}$"))

	const httpServerShutdownTimeout = 10 * time.Second // 10s in case test worker is slow
	settings := Settings{
		BlockProfileRate: intPtr(0),
		MutexProfileRate: intPtr(0),
		HTTPServer: httpserver.Settings{
			Address:         address,
			Logger:          logger,
			ShutdownTimeout: httpServerShutdownTimeout,
		},
	}

	server, err := New(settings)
	require.NoError(t, err)
	require.NotNil(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan struct{})

	go server.Run(ctx, ready, done)

	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("server crashed before being ready: %s", err)
	}

	serverAddress := server.GetAddress()

	const clientTimeout = 2 * time.Second
	httpClient := &http.Client{Timeout: clientTimeout}

	pathsToCheck := []string{
		"debug/pprof/",
		"debug/pprof/cmdline",
		"debug/pprof/profile?seconds=1",
		"debug/pprof/symbol",
		"debug/pprof/trace?seconds=1",
		"debug/pprof/block",
		"debug/pprof/goroutine",
		"debug/pprof/heap",
		"debug/pprof/threadcreate",
	}

	type httpResult struct {
		url      string
		response *http.Response
		err      error
	}
	results := make(chan httpResult)

	for _, pathToCheck := range pathsToCheck {
		url := "http://" + serverAddress + "/" + pathToCheck

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)

		go func(client *http.Client, request *http.Request, results chan<- httpResult) {
			response, err := client.Do(request) //nolint:bodyclose
			results <- httpResult{
				url:      request.URL.String(),
				response: response,
				err:      err,
			}
		}(httpClient, request, results)
	}

	for range pathsToCheck {
		httpResult := <-results

		require.NoErrorf(t, httpResult.err, "unexpected error for URL %s: %s", httpResult.url, httpResult.err)
		assert.Equalf(t, http.StatusOK, httpResult.response.StatusCode,
			"unexpected status code for URL %s: %s", httpResult.url, http.StatusText(httpResult.response.StatusCode))

		b, err := io.ReadAll(httpResult.response.Body)
		require.NoErrorf(t, err, "unexpected error for URL %s: %s", httpResult.url, err)
		assert.NotEmptyf(t, b, "response body is empty for URL %s", httpResult.url)

		err = httpResult.response.Body.Close()
		assert.NoErrorf(t, err, "unexpected error for URL %s: %s", httpResult.url, err)
	}

	cancel()
	<-done
}

func Test_Server_BadSettings(t *testing.T) {
	t.Parallel()

	settings := Settings{
		BlockProfileRate: intPtr(-1),
		MutexProfileRate: intPtr(0),
	}

	server, err := New(settings)
	assert.Nil(t, server)
	assert.ErrorContains(t, err, "block profile rate cannot be negative")
	const expectedErrMessage = "pprof settings failed validation: block profile rate cannot be negative"
	assert.EqualError(t, err, expectedErrMessage)
}
