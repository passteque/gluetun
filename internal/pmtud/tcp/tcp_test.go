//go:build linux

package tcp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/pmtud/ip"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func Test_runTest(t *testing.T) {
	t.Parallel()

	localNonListenPort := reserveClosedPort(t)

	noopLogger := &noopLogger{}

	netlinker := netlink.New(noopLogger)
	loopbackMTU, err := findLoopbackMTU(netlinker)
	require.NoError(t, err, "finding loopback IPv4 MTU")
	defaultMTU, err := findDefaultRouteMTU(netlinker)
	require.NoError(t, err, "finding default route MTU")

	ctx, cancel := context.WithCancel(t.Context())

	familyToFD, stop, err := startRawSockets([]int{constants.AF_INET, constants.AF_INET6}, excludeMark)
	require.NoError(t, err)

	tracker := newTracker(familyToFD)
	trackerCh := make(chan error)
	go func() {
		trackerCh <- tracker.listen(ctx)
	}()

	// Our local ethernet MTU could be 1500, and the server could advertise
	// an MSS of 1400, but the real link to the server could have an MTU of 1300,
	// so we need to adjust our test so it passes. We are not actually path MTU
	// discovering here, just testing that we can receive the expected TCP packets
	// for a given MTU.
	const mtuSafetyBuffer = 200

	t.Cleanup(func() {
		stop()
		cancel() // stop listening
		err = <-trackerCh
		require.NoError(t, err)
	})

	testCases := map[string]struct {
		timeout time.Duration
		server  netip.AddrPort
		mtu     uint32
		success bool
	}{
		"local_not_listening": {
			timeout: time.Hour,
			server:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), localNonListenPort),
			mtu:     loopbackMTU,
			success: true,
		},
		"remote_not_listening": {
			timeout: 50 * time.Millisecond,
			server:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 12345),
			mtu:     defaultMTU - mtuSafetyBuffer,
		},
		"1.1.1.1:443": {
			timeout: 5 * time.Second,
			server:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 443),
			mtu:     defaultMTU - mtuSafetyBuffer,
			success: true,
		},
		"1.1.1.1:80": {
			timeout: 5 * time.Second,
			server:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 80),
			mtu:     defaultMTU - mtuSafetyBuffer,
			success: true,
		},
		"8.8.8.8:443": {
			timeout: 5 * time.Second,
			server:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 443),
			mtu:     defaultMTU - mtuSafetyBuffer,
			success: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			dst := testCase.server
			fd := familyToFD[ip.GetFamily(dst)]

			fw := getFirewall(t)
			logger := NewMockLogger(ctrl)

			ctx, cancel := context.WithTimeout(t.Context(), testCase.timeout)
			defer cancel()
			err := runTest(ctx, dst, testCase.mtu, excludeMark,
				fd, tracker, fw, logger)
			if testCase.success {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
