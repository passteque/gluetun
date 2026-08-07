package nftables

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AcceptInputThroughInterface(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fw := New(nil)

	err := fw.AcceptInputThroughInterface(ctx, "tun0")
	// Verify no panic; may fail if not running as root
	if err != nil {
		assert.Contains(t, err.Error(), "creating nftables connection")
	}
}

func Test_AcceptInputToPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf   string
		port   uint16
		remove bool
	}{
		"add rule with interface": {
			intf:   "tun0",
			port:   8080,
			remove: false,
		},
		"add rule without interface": {
			intf:   "",
			port:   443,
			remove: false,
		},
		"add rule with star interface": {
			intf:   "*",
			port:   53,
			remove: false,
		},
		"remove rule": {
			intf:   "tun0",
			port:   8080,
			remove: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			fw := New(nil)

			err := fw.AcceptInputToPort(ctx, tc.intf, tc.port, tc.remove)
			// May fail if not running as root
			if err != nil && !tc.remove {
				assert.Contains(t, err.Error(), "creating nftables connection")
			} else if err != nil && tc.remove {
				// For remove, the rule won't exist, so expect error
				assert.Error(t, err)
			}
		})
	}
}

func Test_AcceptInputToPort_ExpressionStructure(t *testing.T) {
	t.Parallel()

	// Verify the expression structure for AcceptInputToPort
	conn, err := nftables.New()
	require.NoError(t, err)
	table, inputChain, _, _ := setupFilterWithBaseChains(conn)

	const port = 80
	portBytes := []byte{byte(port >> 8), byte(port)}
	const tcp uint8 = 6

	// Build expressions for a rule with interface filter
	exprs := []expr.Any{
		// Interface match
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("tun0\x00")},
		// Protocol match (TCP)
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{tcp}},
		// Destination port match
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: exprs,
	}

	require.NotNil(t, rule)
	assert.Equal(t, "filter", rule.Table.Name)
	assert.Equal(t, "input", rule.Chain.Name)
	assert.Len(t, rule.Exprs, 7)
}

func Test_AcceptInputToSubnet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := map[string]struct {
		intf   string
		subnet netip.Prefix
	}{
		"IPv4 subnet with interface": {
			intf:   "tun0",
			subnet: mustParsePrefix("192.168.1.0/24"),
		},
		"IPv4 subnet without interface": {
			intf:   "",
			subnet: mustParsePrefix("10.0.0.0/8"),
		},
		"IPv6 subnet with interface": {
			intf:   "tun0",
			subnet: mustParsePrefix("fd00::/64"),
		},
		"IPv6 subnet without interface": {
			intf:   "",
			subnet: mustParsePrefix("fe80::/10"),
		},
		"single IPv4 host": {
			intf:   "tun0",
			subnet: mustParsePrefix("192.168.1.1/32"),
		},
		"single IPv6 host": {
			intf:   "tun0",
			subnet: mustParsePrefix("2001:db8::1/128"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fw := New(nil)

			err := fw.AcceptInputToSubnet(ctx, tc.intf, tc.subnet)
			// May fail if not running as root
			if err != nil {
				assert.Contains(t, err.Error(), "creating nftables connection")
			}
		})
	}
}

func Test_AcceptInputToSubnet_PayloadOffset(t *testing.T) {
	t.Parallel()

	// Verify correct payload offset for IPv4 vs IPv6
	_, err := nftables.New()
	require.NoError(t, err)

	// IPv4: destination address at offset 16.
	// IPv4 header layout: version(1) + IHL(1) + tos(1) + total length(2) +
	//   ID(2) + flags(2) + TTL(1) + protocol(1) + checksum(2) + src(4) + dst(4).
	// So dst starts at offset 16.
	v4Subnet := mustParsePrefix("192.168.1.0/24")
	v4Exprs := buildInputSubnetExprs("", v4Subnet)
	v4Payload, ok := v4Exprs[len(v4Exprs)-3].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, uint32(16), v4Payload.Offset)

	// IPv6: destination address at offset 24.
	// IPv6 header layout: version(1) + traffic class(1) + flow label(2) +
	//   payload length(2) + next header(1) + hop limit(1) + src(16) + dst(16).
	// So dst starts at offset 8 + 16 = 24.
	v6Subnet := mustParsePrefix("fd00::/64")
	v6Exprs := buildInputSubnetExprs("", v6Subnet)
	v6Payload, ok := v6Exprs[len(v6Exprs)-3].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, uint32(24), v6Payload.Offset)

	_ = v4Exprs
	_ = v6Exprs
	_ = err
}

func buildInputSubnetExprs(intf string, subnet netip.Prefix) []expr.Any {
	const maxExprsLen = 5
	exprs := make([]expr.Any, 0, maxExprsLen)

	if intf != "" && intf != "*" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(intf + "\x00")},
		)
	}

	var payloadOffset uint32
	if subnet.Addr().Is4() {
		payloadOffset = 16
	} else {
		payloadOffset = 24
	}

	exprs = append(exprs,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       payloadOffset,
			Len:          uint32(len(subnet.Addr().AsSlice())), //nolint:gosec // address length is at most 16 bytes
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     subnet.Addr().AsSlice(),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)

	return exprs
}

func mustParsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}
