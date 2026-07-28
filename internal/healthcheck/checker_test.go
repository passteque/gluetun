package healthcheck

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
