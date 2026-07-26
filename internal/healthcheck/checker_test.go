package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/healthcheck/icmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
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

// Test_Checker_smallPeriodicCheck_raceWithSetConfig reproduces
// https://github.com/qdm12/gluetun/issues/3395: SetConfig (called by the
// VPN loop on every reconnect) writes smallCheckType and other fields under
// configMutex, while smallPeriodicCheck (called from the Checker's own
// periodic goroutine) used to read - and on ICMP-not-permitted, write -
// the same fields without holding the lock at all.
//
// Without the fix in checker.go, `go test -race` reports a DATA RACE on
// this test, and the test can also panic with "unknown small check type: "
// (the exact symptom from the issue): a reader observing a torn/zero
// string value for smallCheckType.
//
// The fake ICMP echoer always returns icmp.ErrNotPermitted so every call
// to smallPeriodicCheck exercises the racy fallback-to-DNS write path,
// while the fake DNS checker returns instantly so the test runs fast
// (no real network or raw socket access is used).
func Test_Checker_smallPeriodicCheck_raceWithSetConfig(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	echoer := NewMockicmpEchoer(ctrl)
	echoer.EXPECT().Echo(gomock.Any(), gomock.Any()).
		Return(fmt.Errorf("listening for ICMP packets: %w", icmp.ErrNotPermitted)).
		AnyTimes()

	dnsClient := NewMockdnsChecker(ctrl)
	dnsClient.EXPECT().Check(gomock.Any()).Return(nil).AnyTimes()

	logger := NewMockLogger(ctrl)
	logger.EXPECT().Debugf(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()

	checker := &Checker{
		echoer:    echoer,
		dnsClient: dnsClient,
		logger:    logger,
	}

	targetIPs := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	ctx := context.Background()

	// Start() (not exercised directly here) is the only production caller of
	// smallPeriodicCheck, and it panics if SetConfig hasn't been called at
	// least once first - so this direct-call test must uphold the same
	// precondition before racing further SetConfig calls against it.
	checker.SetConfig([]string{"example.com:443"}, targetIPs, smallCheckICMP, false)

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iterations {
			checker.SetConfig([]string{"example.com:443"}, targetIPs, smallCheckICMP, false)
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			_ = checker.smallPeriodicCheck(ctx)
		}
	}()
	wg.Wait()
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
