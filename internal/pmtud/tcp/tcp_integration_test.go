//go:build integration

package tcp

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/firewall"
	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PathMTUDiscover(t *testing.T) {
	t.Parallel()

	const tryTimeout = time.Second
	deadline, ok := t.Deadline()
	if ok {
		timeLeft := time.Until(deadline)
		const maxTimeNeeded = tryTimeout * 4 // MSS discovery + 3 MTU tries
		require.GreaterOrEqual(t, timeLeft, maxTimeNeeded,
			"not enough time remaining for TCP PMTUD test, need %s and got %s",
			maxTimeNeeded, timeLeft)
	}

	logger := log.New(log.SetLevel(log.LevelDebug))

	cmder := command.New()
	fw, err := firewall.NewConfig(t.Context(), logger, logger, cmder, nil, nil)
	if errors.Is(err, iptables.ErrNotSupported) {
		t.Skip("iptables not installed, skipping TCP PMTUD tests")
	}
	require.NoError(t, err, "creating firewall config")

	dsts := []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 443),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 443),
		netip.AddrPortFrom(netip.MustParseAddr("2606:4700:4700::1111"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("2001:4860:4860::8888"), 443),
	}
	const minMTU = constants.MinIPv6MTU
	const maxMTU = constants.MaxEthernetFrameSize
	mtu, err := PathMTUDiscover(t.Context(), dsts, minMTU, maxMTU, tryTimeout, fw, logger)
	require.NoError(t, err, "discovering path MTU")
	assert.Greater(t, mtu, uint32(0), "MTU should be greater than 0")
	t.Logf("discovered path MTU is %d", mtu)
}
