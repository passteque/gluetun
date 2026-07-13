package healthcheck

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_startupCheckWithRetries(t *testing.T) {
	t.Parallel()

	t.Run("success_on_later_retry", func(t *testing.T) {
		t.Parallel()

		attempts := 0
		check := func(context.Context) error {
			attempts++
			if attempts < 3 {
				return errors.New("not ready")
			}
			return nil
		}

		err := startupCheckWithRetries(t.Context(), time.Second, 100*time.Millisecond, time.Millisecond, check)

		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})

	t.Run("total_budget_exhaustion", func(t *testing.T) {
		t.Parallel()

		attempts := 0
		check := func(context.Context) error {
			attempts++
			return errors.New("not ready")
		}
		const totalBudget = 30 * time.Millisecond
		const minimumDuration = 25 * time.Millisecond
		start := time.Now()

		err := startupCheckWithRetries(t.Context(), totalBudget, time.Second, 5*time.Millisecond, check)

		require.Error(t, err)
		assert.ErrorContains(t, err, "not ready")
		assert.Greater(t, attempts, 1)
		assert.GreaterOrEqual(t, time.Since(start), minimumDuration)
	})

	t.Run("immediate_success_returns_fast", func(t *testing.T) {
		t.Parallel()

		const maximumDuration = 250 * time.Millisecond
		start := time.Now()
		err := startupCheckWithRetries(t.Context(), time.Second, time.Second, 500*time.Millisecond,
			func(context.Context) error { return nil })

		assert.NoError(t, err)
		assert.Less(t, time.Since(start), maximumDuration)
	})

	t.Run("context_cancellation_aborts_promptly", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		checkStarted := make(chan struct{})
		check := func(ctx context.Context) error {
			close(checkStarted)
			<-ctx.Done()
			return ctx.Err()
		}
		go func() {
			<-checkStarted
			cancel()
		}()
		const maximumDuration = 250 * time.Millisecond
		start := time.Now()

		err := startupCheckWithRetries(ctx, time.Second, time.Second, 500*time.Millisecond, check)

		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Less(t, time.Since(start), maximumDuration)
	})
}

func Test_Checker_fullcheck(t *testing.T) {
	t.Parallel()

	t.Run("canceled real dialer", func(t *testing.T) {
		t.Parallel()

		dialer := &net.Dialer{}
		addresses := []string{"badaddress:9876", "cloudflare.com:443", "google.com:443"}

		checker := &Checker{
			dialer:       dialer,
			tlsDialAddrs: addresses,
		}

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := checker.fullPeriodicCheck(canceledCtx)

		require.Error(t, err)
		assert.EqualError(t, err, "TCP+TLS dial: context canceled")
	})

	t.Run("dial localhost:0", func(t *testing.T) {
		t.Parallel()

		const timeout = 100 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		listenConfig := &net.ListenConfig{}
		listener, err := listenConfig.Listen(ctx, "tcp4", "localhost:0")
		require.NoError(t, err)
		t.Cleanup(func() {
			err = listener.Close()
			assert.NoError(t, err)
		})

		listeningAddress := listener.Addr()

		dialer := &net.Dialer{}
		checker := &Checker{
			dialer:       dialer,
			tlsDialAddrs: []string{listeningAddress.String()},
		}

		err = checker.fullPeriodicCheck(ctx)

		assert.NoError(t, err)
	})
}

func Test_makeAddressToDial(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		address       string
		addressToDial string
		errMessage    string
	}{
		"host without port": {
			address:       "test.com",
			addressToDial: "test.com:443",
		},
		"host with port": {
			address:       "test.com:80",
			addressToDial: "test.com:80",
		},
		"bad address": {
			address:    "test.com::",
			errMessage: "splitting host and port from address: address test.com::: too many colons in address",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addressToDial, err := makeAddressToDial(testCase.address)

			assert.Equal(t, testCase.addressToDial, addressToDial)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_tcpTLSCheckWithDialContext_closesConnectionOnHandshakeError(t *testing.T) {
	t.Parallel()

	connection := &failingTLSConnection{}
	dialContext := func(_ context.Context, network, address string) (net.Conn, error) {
		assert.Equal(t, "tcp4", network)
		assert.Equal(t, "example.com:443", address)
		return connection, nil
	}

	err := tcpTLSCheckWithDialContext(t.Context(), dialContext, "example.com:443")

	require.Error(t, err)
	assert.ErrorContains(t, err, "running TLS handshake")
	assert.True(t, connection.closed)
}

type failingTLSConnection struct {
	closed bool
}

func (c *failingTLSConnection) Read([]byte) (int, error) {
	return 0, errors.New("TLS read error")
}

func (c *failingTLSConnection) Write(buffer []byte) (int, error) {
	return len(buffer), nil
}

func (c *failingTLSConnection) Close() error {
	c.closed = true
	return nil
}

func (c *failingTLSConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *failingTLSConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *failingTLSConnection) SetDeadline(time.Time) error {
	return nil
}

func (c *failingTLSConnection) SetReadDeadline(time.Time) error {
	return nil
}

func (c *failingTLSConnection) SetWriteDeadline(time.Time) error {
	return nil
}
