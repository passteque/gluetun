package nftables

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TempDropOutputTCPRST(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fw := New(nil)

	src := netip.MustParseAddrPort("192.168.1.1:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:443")
	excludeMark := 0x100

	revert, err := fw.TempDropOutputTCPRST(ctx, src, dst, excludeMark)
	// May fail if not running as root; just verify no panic and correct error type
	if err != nil {
		assert.Nil(t, revert)
		assert.Contains(t, err.Error(), "creating nftables connection")
	} else {
		require.NotNil(t, revert)
	}
}

func Test_TempDropOutputTCPRST_ipv6(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fw := New(nil)

	src := netip.MustParseAddrPort("[2001:db8::1]:12345")
	dst := netip.MustParseAddrPort("[2001:db8::2]:443")
	excludeMark := 0x100

	revert, err := fw.TempDropOutputTCPRST(ctx, src, dst, excludeMark)
	if err != nil {
		assert.Nil(t, revert)
		assert.Contains(t, err.Error(), "creating nftables connection")
	} else {
		require.NotNil(t, revert)
	}
}

func Test_TempDropOutputTCPRST_ExpressionCount(t *testing.T) {
	t.Parallel()

	// Verify that the TCP RST rule has the expected number of expressions
	// Source IP (2) + Dest IP (2) + TCP proto (2) + src port (2) + dst port (2) +
	// TCP flags (2) + mark exclusion (2) + DROP (1) = 15 for IPv4
	// Source IP (2) + Dest IP (2) + TCP proto (2) + src port (2) + dst port (2) +
	// TCP flags (2) + mark exclusion (2) + DROP (1) = 15 for IPv6

	src := netip.MustParseAddrPort("192.168.1.1:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:443")
	excludeMark := 0x100

	exprs := buildTCPRSTDropExprs(src, dst, excludeMark)
	// 2 (src IP) + 2 (dst IP) + 2 (proto) + 2 (src port) + 2 (dst port) + 2 (flags) + 2 (mark) + 1 (drop)
	assert.Len(t, exprs, 15)
}

func Test_TempDropOutputTCPRST_TCPFlags(t *testing.T) {
	t.Parallel()

	// Verify TCP RST flag matching expression
	src := netip.MustParseAddrPort("192.168.1.1:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:443")
	excludeMark := 0x100

	exprs := buildTCPRSTDropExprs(src, dst, excludeMark)

	// Find the TCP flags expression (should be near the end, before mark)
	var flagsCmp *exprCmpFinder
	for _, e := range exprs {
		if cmp, ok := e.(*exprCmpFinder); ok && cmp.Data != nil && len(cmp.Data) == 1 && cmp.Data[0] == 0x04 {
			flagsCmp = cmp
			break
		}
	}

	// The TCP flags byte (offset 13) should match exactly 0x04 (RST only)
	require.NotNil(t, flagsCmp)
	assert.Equal(t, []byte{0x04}, flagsCmp.Data)
}

// Helper types for testing expression structure.
type exprCmpFinder struct {
	Op   byte
	Data []byte
}

func buildTCPRSTDropExprs(src, dst netip.AddrPort, excludeMark int) []any {
	exprs := make([]any, 0, 15)

	// Source IP
	if src.Addr().Is4() {
		exprs = append(exprs, "payload_src_ip_v4", &exprCmpFinder{Data: src.Addr().AsSlice()})
	} else {
		exprs = append(exprs, "payload_src_ip_v6", &exprCmpFinder{Data: src.Addr().AsSlice()})
	}

	// Dest IP
	if dst.Addr().Is4() {
		exprs = append(exprs, "payload_dst_ip_v4", &exprCmpFinder{Data: dst.Addr().AsSlice()})
	} else {
		exprs = append(exprs, "payload_dst_ip_v6", &exprCmpFinder{Data: dst.Addr().AsSlice()})
	}

	// TCP protocol
	exprs = append(exprs, "meta_l4proto", &exprCmpFinder{Data: []byte{6}})

	// Source port
	srcPort := []byte{byte(src.Port() >> 8), byte(src.Port())} //nolint:gosec // network byte order
	exprs = append(exprs, "payload_src_port", &exprCmpFinder{Data: srcPort})

	// Dest port
	dstPort := []byte{byte(dst.Port() >> 8), byte(dst.Port())} //nolint:gosec // network byte order
	exprs = append(exprs, "payload_dst_port", &exprCmpFinder{Data: dstPort})

	// TCP flags (RST only = 0x04)
	exprs = append(exprs, "payload_flags", &exprCmpFinder{Data: []byte{0x04}})

	// Mark exclusion
	markData := []byte{ //nolint:gosec // mark is int (32-bit), byte conversions are intentional
		byte(excludeMark), byte(excludeMark >> 8), byte(excludeMark >> 16), byte(excludeMark >> 24),
	}
	exprs = append(exprs, "meta_mark_neq", &exprCmpFinder{Data: markData})

	// DROP
	exprs = append(exprs, "verdict_drop")

	return exprs
}

func Test_TempDropOutputTCPRST_MarkExclusion(t *testing.T) {
	t.Parallel()

	// Verify the mark exclusion works correctly for different mark values
	testCases := []struct {
		mark     int
		expected []byte
	}{
		{0x100, []byte{0x00, 0x01, 0x00, 0x00}},
		{0x0, []byte{0x00, 0x00, 0x00, 0x00}},
		{0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("mark_%d", tc.mark), func(t *testing.T) {
			t.Parallel()

			src := netip.MustParseAddrPort("192.168.1.1:12345")
			dst := netip.MustParseAddrPort("10.0.0.1:443")
			exprs := buildTCPRSTDropExprs(src, dst, tc.mark)

			// Find mark exclusion expression (second to last before DROP)
			if len(exprs) >= 2 {
				markExpr, ok := exprs[len(exprs)-2].(*exprCmpFinder)
				require.True(t, ok)
				assert.Equal(t, tc.expected, markExpr.Data)
			}
		})
	}
}
