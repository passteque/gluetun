//go:build linux

package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func Test_parseProtocol(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		protocol      string
		expected      uint8
		expectedError string
	}{
		"tcp":        {protocol: "tcp", expected: protocolTCP},
		"tcp_client": {protocol: "tcp-client", expected: protocolTCP},
		"udp":        {protocol: "udp", expected: protocolUDP},
		"unknown": {
			protocol:      "icmp",
			expectedError: "unsupported protocol: icmp",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			number, err := parseProtocol(testCase.protocol)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, number)
		})
	}
}

func Test_nfprotoGuardExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		isIPv4   bool
		expected []expr.Any
	}{
		"ipv4": {
			isIPv4: true,
			expected: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNumberIPv4}},
			},
		},
		"ipv6": {
			isIPv4: false,
			expected: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNumberIPv6}},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, nfprotoGuardExprs(testCase.isIPv4))
		})
	}
}

func Test_protocolExprs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolTCP}},
	}, protocolExprs(protocolTCP))

	assert.Equal(t, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolUDP}},
	}, protocolExprs(protocolUDP))
}

func Test_sourceIPExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		addr     netip.Addr
		expected []expr.Any
	}{
		"ipv4": {
			addr: netip.MustParseAddr("1.2.3.4"),
			expected: append(nfprotoGuardExprs(true),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
			),
		},
		"ipv6": {
			addr: netip.MustParseAddr("2001:db8::1"),
			expected: append(nfprotoGuardExprs(false),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netip.MustParseAddr("2001:db8::1").AsSlice()},
			),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, sourceIPExprs(testCase.addr))
		})
	}
}

func Test_destinationIPExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		addr     netip.Addr
		expected []expr.Any
	}{
		"ipv4": {
			addr: netip.MustParseAddr("1.2.3.4"),
			expected: append(nfprotoGuardExprs(true),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1, 2, 3, 4}},
			),
		},
		"ipv6": {
			addr: netip.MustParseAddr("2001:db8::1"),
			expected: append(nfprotoGuardExprs(false),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netip.MustParseAddr("2001:db8::1").AsSlice()},
			),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, destinationIPExprs(testCase.addr))
		})
	}
}

func Test_destinationSubnetExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		subnet   netip.Prefix
		expected []expr.Any
	}{
		"ipv4_24": {
			subnet: netip.MustParsePrefix("192.168.1.0/24"),
			expected: append(nfprotoGuardExprs(true),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: []byte{0xff, 0xff, 0xff, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00},
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1, 0}},
			),
		},
		"ipv4_32": {
			subnet: netip.MustParsePrefix("192.168.1.5/32"),
			expected: append(nfprotoGuardExprs(true),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: []byte{0xff, 0xff, 0xff, 0xff}, Xor: []byte{0x00, 0x00, 0x00, 0x00},
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1, 5}},
			),
		},
		"host_bits_are_masked_off": {
			subnet: netip.MustParsePrefix("192.168.1.5/24"),
			expected: append(nfprotoGuardExprs(true),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: []byte{0xff, 0xff, 0xff, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00},
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1, 0}},
			),
		},
		"ipv6_64": {
			subnet: netip.MustParsePrefix("2001:db8:1:2::/64"),
			expected: append(nfprotoGuardExprs(false),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 16,
					Mask: []byte{
						0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					},
					Xor: make([]byte, 16),
				},
				&expr.Cmp{
					Op: expr.CmpOpEq, Register: 1,
					Data: netip.MustParsePrefix("2001:db8:1:2::/64").Masked().Addr().AsSlice(),
				},
			),
		},
		"ipv6_multicast_104": {
			subnet: netip.MustParsePrefix("ff02::1:ff00:0/104"),
			expected: append(nfprotoGuardExprs(false),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Bitwise{
					SourceRegister: 1, DestRegister: 1, Len: 16,
					Mask: []byte{
						0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
						0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
					},
					Xor: make([]byte, 16),
				},
				&expr.Cmp{
					Op: expr.CmpOpEq, Register: 1,
					Data: netip.MustParsePrefix("ff02::1:ff00:0/104").Masked().Addr().AsSlice(),
				},
			),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, destinationSubnetExprs(testCase.subnet))
		})
	}
}

func Test_sourceAndDestinationPortExprs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x07, 0xb9}}, // 1977
	}, sourcePortExprs(1977))

	assert.Equal(t, []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x07, 0xb9}}, // 1977
	}, destinationPortExprs(1977))
}

func Test_interfaceExprs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf           string
		expectedInput  []expr.Any
		expectedOutput []expr.Any
	}{
		"empty": {intf: ""},
		"all":   {intf: "*"},
		"named": {
			intf: "eth0",
			expectedInput: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("eth0\x00")},
			},
			expectedOutput: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("eth0\x00")},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expectedInput, inputInterfaceExprs(testCase.intf))
			assert.Equal(t, testCase.expectedOutput, outputInterfaceExprs(testCase.intf))
		})
	}
}

func Test_cidrMask(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		bits     int
		addrLen  int
		expected []byte
	}{
		"zero": {
			bits:     0,
			addrLen:  4,
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		"half_byte": {
			bits:     4,
			addrLen:  4,
			expected: []byte{0xf0, 0x00, 0x00, 0x00},
		},
		"one_byte": {
			bits:     8,
			addrLen:  4,
			expected: []byte{0xff, 0x00, 0x00, 0x00},
		},
		"ipv4_24": {
			bits:     24,
			addrLen:  4,
			expected: []byte{0xff, 0xff, 0xff, 0x00},
		},
		"ipv4_full": {
			bits:     32,
			addrLen:  4,
			expected: []byte{0xff, 0xff, 0xff, 0xff},
		},
		"ipv6_104": {
			bits:    104,
			addrLen: 16,
			expected: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, cidrMask(testCase.bits, testCase.addrLen))
		})
	}
}
