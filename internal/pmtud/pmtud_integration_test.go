//go:build integration

package pmtud

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/firewall"
	"github.com/qdm12/gluetun/internal/firewall/iptables"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/require"
)

func Test_PathMTUDiscover(t *testing.T) {
	t.Parallel()
	const physicalLinkMTU = 1500
	const timeout = time.Second

	logger := log.New(log.SetLevel(log.LevelDebug))

	cmder := command.New()
	fw, err := firewall.NewConfig(t.Context(), logger, logger, cmder, nil, nil)
	if errors.Is(err, iptables.ErrNotSupported) {
		t.Skip("iptables not installed, skipping TCP PMTUD tests")
	}
	require.NoError(t, err, "creating firewall config")

	icmpAddrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}
	tcpAddrs := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:80"),
	}
	mtu, err := PathMTUDiscover(t.Context(), icmpAddrs, tcpAddrs,
		physicalLinkMTU, timeout, fw, logger)
	require.NoError(t, err)
	t.Log("MTU found:", mtu)
}
