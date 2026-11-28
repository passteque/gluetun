package httpproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Loop_slowHTTPRequestBody(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	upstream := httptest.NewServer(http.HandlerFunc(func(
		responseWriter http.ResponseWriter, request *http.Request,
	) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
			return
		}
		responseWriter.WriteHeader(http.StatusOK)
		_, _ = responseWriter.Write(body)
	}))
	t.Cleanup(upstream.Close)

	proxyAddress := reserveTCPAddress(t)

	var allSettings settings.Settings
	allSettings.SetDefaults()
	proxySettings := allSettings.HTTPProxy
	proxySettings.ListeningAddress = proxyAddress

	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("listening on " + proxyAddress)
	loop := NewLoop(logger, proxySettings)

	runCtx, runCancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go loop.Run(runCtx, runDone)
	t.Cleanup(func() {
		runCancel()
		<-runDone
	})

	_, err := loop.ApplyStatus(ctx, constants.Running)
	require.NoError(t, err)
	waitForTCPListening(t, proxyAddress)

	proxyURL, err := url.Parse("http://" + proxyAddress)
	require.NoError(t, err)

	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	t.Cleanup(transport.CloseIdleConnections)

	const clientTimeout = 15 * time.Second
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   clientTimeout,
	}

	// Stream a POST body across a pause exceeding the old 3s default ReadTimeout.
	const slowBodyPause = 3500 * time.Millisecond
	firstChunk := []byte("first-upload-chunk-")
	secondChunk := []byte("second-upload-chunk")
	expectedBody := append(append([]byte(nil), firstChunk...), secondChunk...)

	pipeReader, pipeWriter := io.Pipe()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		_, writeErr := pipeWriter.Write(firstChunk)
		if writeErr != nil {
			return
		}
		timer := time.NewTimer(slowBodyPause)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			_ = pipeWriter.CloseWithError(ctx.Err())
			return
		}
		_, writeErr = pipeWriter.Write(secondChunk)
		if writeErr != nil {
			return
		}
		_ = pipeWriter.Close()
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL+"/upload", pipeReader)
	require.NoError(t, err)
	request.ContentLength = int64(len(expectedBody))

	response, err := httpClient.Do(request)
	_ = pipeReader.Close()
	<-writerDone
	require.NoError(t, err)
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, response.Body.Close())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, expectedBody, responseBody)

	// Send multiple sequential POST requests reusing the same HTTP/1.1 keep-alive connection.
	followUpPayloads := [...]string{
		"follow-up-upload-first",
		"follow-up-upload-second",
	}
	for _, payload := range followUpPayloads {
		var connectionReused bool
		traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				connectionReused = connInfo.Reused
			},
		})
		followUpRequest, err := http.NewRequestWithContext(
			traceCtx, http.MethodPost, upstream.URL+"/upload-next", strings.NewReader(payload),
		)
		require.NoError(t, err)

		followUpResponse, err := httpClient.Do(followUpRequest)
		require.NoError(t, err)
		followUpResponseBody, err := io.ReadAll(followUpResponse.Body)
		require.NoError(t, followUpResponse.Body.Close())
		require.NoError(t, err)
		assert.True(t, connectionReused)
		assert.Equal(t, http.StatusOK, followUpResponse.StatusCode)
		assert.Equal(t, payload, string(followUpResponseBody))
	}
}

func Test_Server_Run(t *testing.T) {
	t.Parallel()

	t.Run("plain_http_get_and_post", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		upstream := httptest.NewServer(http.HandlerFunc(func(
			responseWriter http.ResponseWriter, request *http.Request,
		) {
			switch request.Method {
			case http.MethodGet:
				responseWriter.WriteHeader(http.StatusOK)
				_, _ = responseWriter.Write([]byte("hello-get-response"))
			case http.MethodPost:
				body, err := io.ReadAll(request.Body)
				if err != nil {
					http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
					return
				}
				responseWriter.WriteHeader(http.StatusCreated)
				_, _ = responseWriter.Write(body)
			default:
				http.Error(responseWriter, "unexpected method", http.StatusMethodNotAllowed)
			}
		}))
		t.Cleanup(upstream.Close)

		proxyAddress := reserveTCPAddress(t)
		ctrl := gomock.NewController(t)
		logger := NewMockLogger(ctrl)
		logger.EXPECT().Info("listening on " + proxyAddress)

		runCtx, runCancel := context.WithCancel(ctx)
		server := New(runCtx, proxyAddress, logger, false, false, "", "", time.Second, 0)

		errorCh := make(chan error)
		go server.Run(runCtx, errorCh)
		t.Cleanup(func() {
			runCancel()
			runErr := <-errorCh
			assert.NoError(t, runErr)
		})
		waitForTCPListening(t, proxyAddress)

		proxyURL, err := url.Parse("http://" + proxyAddress)
		require.NoError(t, err)

		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		t.Cleanup(transport.CloseIdleConnections)

		const clientTimeout = 5 * time.Second
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   clientTimeout,
		}

		getRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/get", nil)
		require.NoError(t, err)
		getResponse, err := httpClient.Do(getRequest)
		require.NoError(t, err)
		getBody, err := io.ReadAll(getResponse.Body)
		require.NoError(t, getResponse.Body.Close())
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, getResponse.StatusCode)
		assert.Equal(t, "hello-get-response", string(getBody))

		postPayload := []byte("plain-http-post-body")
		postRequest, err := http.NewRequestWithContext(
			ctx, http.MethodPost, upstream.URL+"/post", bytes.NewReader(postPayload),
		)
		require.NoError(t, err)
		postResponse, err := httpClient.Do(postRequest)
		require.NoError(t, err)
		postBody, err := io.ReadAll(postResponse.Body)
		require.NoError(t, postResponse.Body.Close())
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, postResponse.StatusCode)
		assert.Equal(t, postPayload, postBody)
	})

	t.Run("read_header_timeout_enforced", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		proxyAddress := reserveTCPAddress(t)
		ctrl := gomock.NewController(t)
		logger := NewMockLogger(ctrl)
		logger.EXPECT().Info("listening on " + proxyAddress)

		const shortReadHeaderTimeout = 50 * time.Millisecond
		runCtx, runCancel := context.WithCancel(ctx)
		server := New(runCtx, proxyAddress, logger, false, false, "", "", shortReadHeaderTimeout, 0)

		errorCh := make(chan error)
		go server.Run(runCtx, errorCh)
		t.Cleanup(func() {
			runCancel()
			runErr := <-errorCh
			assert.NoError(t, runErr)
		})
		waitForTCPListening(t, proxyAddress)

		dialer := net.Dialer{}
		connection, err := dialer.DialContext(ctx, "tcp", proxyAddress)
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })

		deadline, hasDeadline := t.Deadline()
		if hasDeadline {
			require.NoError(t, connection.SetDeadline(deadline))
		}

		// Send incomplete HTTP headers without terminating CRLF so the server hits ReadHeaderTimeout.
		_, err = connection.Write([]byte("POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"))
		require.NoError(t, err)

		_, err = connection.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF)
	})
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()

	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

func waitForTCPListening(t *testing.T, address string) {
	t.Helper()

	ctx := t.Context()
	const dialRetryInterval = 10 * time.Millisecond
	dialer := net.Dialer{}
	for {
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return
		}
		timer := time.NewTimer(dialRetryInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			require.NoError(t, ctx.Err())
		}
	}
}
