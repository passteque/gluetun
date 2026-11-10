//go:build linux

package tcp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_findHighestMSSDestination(t *testing.T) {
	t.Parallel()

	skipUnlessRawNetworking(t)

	netlinker := netlink.New(&noopLogger{})
	defaultMTU, err := findDefaultRouteMTU(netlinker)
	require.NoError(t, err, "finding default route MTU")

	ctx, cancel := context.WithCancel(t.Context())

	families := []int{constants.AF_INET, constants.AF_INET6}
	familyToFD, stop, err := startRawSockets(families, excludeMark)
	require.NoError(t, err)

	tracker := newTracker(familyToFD)
	trackerCh := make(chan error)
	go func() {
		trackerCh <- tracker.listen(ctx)
	}()

	t.Cleanup(func() {
		stop()
		cancel() // stop listening
		err = <-trackerCh
		require.NoError(t, err)
	})

	dsts := []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 443),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 443),
		netip.AddrPortFrom(netip.MustParseAddr("2606:4700:4700::1111"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("2001:4860:4860::8888"), 443),
	}
	const timeout = time.Second
	fw := getFirewall(t)
	logger := &noopLogger{}

	dst, mss, err := findHighestMSSDestination(t.Context(), familyToFD, dsts,
		excludeMark, defaultMTU, timeout, tracker, fw, logger)
	require.NoError(t, err, "finding highest MSS destination")
	assert.Contains(t, dsts, dst, "destination should be in the provided list")
	assert.Greater(t, mss, uint32(1000), "MSS should be greater than 1000")
	assert.LessOrEqual(t, mss, constants.MaxEthernetFrameSize,
		"MSS should be less than or equal to the maximum Ethernet frame size	")
}
