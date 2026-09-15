//go:build linux

package nftables

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// expected-value builders mirroring the production composition order.

func expectedMulticastExprs(intf string) []expr.Any {
	const ipv6MulticastPrefix = "ff02::1:ff00:0/104"
	exprs := append(outputInterfaceExprs(intf), destinationSubnetExprs(netip.MustParsePrefix(ipv6MulticastPrefix))...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func expectedVPNExprs(t *testing.T, intf string, connection models.Connection) []expr.Any {
	t.Helper()
	protocol, err := parseProtocol(connection.Protocol)
	require.NoError(t, err)
	exprs := append(outputInterfaceExprs(intf), destinationIPExprs(connection.IP)...)
	exprs = append(exprs, protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(connection.Port)...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func expectedOutputExprs(t *testing.T, protocol, intf string,
	ip netip.Addr, port uint16,
) []expr.Any {
	t.Helper()
	protocolNumber, err := parseProtocol(protocol)
	require.NoError(t, err)
	exprs := append(outputInterfaceExprs(intf), destinationIPExprs(ip)...)
	exprs = append(exprs, protocolExprs(protocolNumber)...)
	exprs = append(exprs, destinationPortExprs(port)...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func expectedOutputIPPortExprs(t *testing.T, protocol, intf string,
	source, destination netip.AddrPort,
) []expr.Any {
	t.Helper()
	protocolNumber, err := parseProtocol(protocol)
	require.NoError(t, err)
	exprs := append(outputInterfaceExprs(intf), sourceIPExprs(source.Addr())...)
	exprs = append(exprs, destinationIPExprs(destination.Addr())...)
	exprs = append(exprs, protocolExprs(protocolNumber)...)
	exprs = append(exprs, sourcePortExprs(source.Port())...)
	exprs = append(exprs, destinationPortExprs(destination.Port())...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func expectedOutputSubnetExprs(intf string, assignedIP netip.Addr, subnet netip.Prefix) []expr.Any {
	exprs := append(outputInterfaceExprs(intf), sourceIPExprs(assignedIP)...)
	exprs = append(exprs, destinationSubnetExprs(subnet)...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func expectedOutputIntfExprs(intf string) []expr.Any {
	return append(outputInterfaceExprs(intf), &expr.Verdict{Kind: expr.VerdictAccept})
}

// mock setup helpers for the filter table.

func expectNewGluetunTable(mockConn *MockConn) {
	mockConn.EXPECT().ListTables().Return(nil, nil)
	mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
		return table
	})
	mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
		return chain
	}).Times(3)
}

func expectExistingGluetunTable(mockConn *MockConn) {
	mockConn.EXPECT().ListTables().Return(testGluetunTables(), nil)
	mockConn.EXPECT().ListChains().Return(testBaseChainsAll(), nil)
}

func Test_AcceptIpv6MulticastOutput(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf string
	}{
		"named_interface": {intf: "eth0"},
		"empty_interface": {intf: ""},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			expectNewGluetunTable(mockConn)

			var addedRule *nftables.Rule
			mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRule = rule
				return rule
			})
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptIpv6MulticastOutput(t.Context(), testCase.intf)

			assert.NoError(t, err)
			assert.NotNil(t, addedRule)
			assert.Equal(t, outputChainName, addedRule.Chain.Name)
			assert.Equal(t, expectedMulticastExprs(testCase.intf), addedRule.Exprs)
			assert.Len(t, f.rules, 1)
		})
	}
}

func Test_AcceptOutputTrafficToVPN(t *testing.T) {
	t.Parallel()

	connection := models.Connection{
		Type:     "wireguard",
		IP:       netip.MustParseAddr("10.8.0.1"),
		Port:     51820,
		Protocol: "udp",
	}

	testCases := map[string]struct {
		intf   string
		remove bool
	}{
		"add_with_interface": {intf: "tun0"},
		"add_no_interface":   {intf: ""},
		"remove":             {intf: "tun0", remove: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			expectedExprs := expectedVPNExprs(t, testCase.intf, connection)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			var addedRule *nftables.Rule
			if testCase.remove {
				f.rules = []*nftables.Rule{{Exprs: expectedExprs}}
				expectExistingGluetunTable(mockConn)
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
					[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
				)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
			} else {
				expectNewGluetunTable(mockConn)
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRule = rule
					return rule
				})
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptOutputTrafficToVPN(t.Context(), testCase.intf, connection, testCase.remove)

			assert.NoError(t, err)
			if !testCase.remove {
				assert.NotNil(t, addedRule)
				assert.Equal(t, outputChainName, addedRule.Chain.Name)
				assert.Equal(t, expectedExprs, addedRule.Exprs)
				assert.Len(t, f.rules, 1)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}

func Test_AcceptOutput(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		protocol string
		intf     string
		ip       netip.Addr
		port     uint16
		remove   bool
	}{
		"tcp_ipv4_with_interface": {
			protocol: "tcp", intf: "tun0",
			ip: netip.MustParseAddr("8.8.8.8"), port: 443,
		},
		"udp_ipv4_no_interface": {
			protocol: "udp", intf: "",
			ip: netip.MustParseAddr("1.1.1.1"), port: 53,
		},
		"tcp_ipv6": {
			protocol: "tcp", intf: "",
			ip: netip.MustParseAddr("2001:4860:4860::8888"), port: 443,
		},
		"remove": {
			protocol: "tcp", intf: "tun0",
			ip: netip.MustParseAddr("8.8.8.8"), port: 443,
			remove: true,
		},
		"invalid_protocol": {
			protocol: "icmp", intf: "",
			ip: netip.MustParseAddr("8.8.8.8"), port: 443,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			if testCase.protocol == "icmp" {
				err := f.AcceptOutput(t.Context(), testCase.protocol, testCase.intf,
					testCase.ip, testCase.port, testCase.remove)
				assert.ErrorContains(t, err, "unsupported protocol: icmp")
				return
			}

			expectedExprs := expectedOutputExprs(t, testCase.protocol, testCase.intf,
				testCase.ip, testCase.port)

			if testCase.remove {
				f.rules = []*nftables.Rule{{Exprs: expectedExprs}}
				expectExistingGluetunTable(mockConn)
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
					[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
				)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
			} else {
				expectNewGluetunTable(mockConn)
			}

			var addedRule *nftables.Rule
			if !testCase.remove {
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRule = rule
					return rule
				})
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptOutput(t.Context(), testCase.protocol, testCase.intf,
				testCase.ip, testCase.port, testCase.remove)

			assert.NoError(t, err)
			if !testCase.remove {
				assert.NotNil(t, addedRule)
				assert.Equal(t, outputChainName, addedRule.Chain.Name)
				assert.Equal(t, expectedExprs, addedRule.Exprs)
				assert.Len(t, f.rules, 1)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}

func Test_AcceptOutputFromIPPortToIPPort(t *testing.T) {
	t.Parallel()

	source := netip.MustParseAddrPort("10.8.0.2:44444")
	destination := netip.MustParseAddrPort("10.8.0.1:51820")

	testCases := map[string]struct {
		protocol      string
		intf          string
		source        netip.AddrPort
		destination   netip.AddrPort
		remove        bool
		expectedError string
	}{
		"udp_with_interface": {
			protocol: "udp", intf: "tun0", source: source, destination: destination,
		},
		"tcp_no_interface": {
			protocol: "tcp", intf: "", source: source, destination: destination,
		},
		"remove": {
			protocol: "udp", intf: "tun0", source: source, destination: destination, remove: true,
		},
		"mixed_address_families": {
			protocol: "tcp", intf: "",
			source:        netip.MustParseAddrPort("10.8.0.2:44444"),
			destination:   netip.MustParseAddrPort("[fd00::1]:51820"),
			expectedError: "source and destination address families do not match",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			if testCase.expectedError != "" {
				err := f.AcceptOutputFromIPPortToIPPort(t.Context(), testCase.protocol, testCase.intf,
					testCase.source, testCase.destination, testCase.remove)
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}

			expectedExprs := expectedOutputIPPortExprs(t, testCase.protocol, testCase.intf,
				testCase.source, testCase.destination)
			if testCase.remove {
				f.rules = []*nftables.Rule{{Exprs: expectedExprs}}
				expectExistingGluetunTable(mockConn)
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
					[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
				)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
			} else {
				expectNewGluetunTable(mockConn)
			}

			var addedRule *nftables.Rule
			if !testCase.remove {
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRule = rule
					return rule
				})
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptOutputFromIPPortToIPPort(t.Context(), testCase.protocol, testCase.intf,
				testCase.source, testCase.destination, testCase.remove)

			assert.NoError(t, err)
			if !testCase.remove {
				assert.NotNil(t, addedRule)
				assert.Equal(t, outputChainName, addedRule.Chain.Name)
				assert.Equal(t, expectedExprs, addedRule.Exprs)
				assert.Len(t, f.rules, 1)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}

func Test_AcceptOutputFromIPToSubnet(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf          string
		assignedIP    netip.Addr
		subnet        netip.Prefix
		remove        bool
		expectedError string
	}{
		"ipv4_with_interface": {
			intf:       "tun0",
			assignedIP: netip.MustParseAddr("10.8.0.2"),
			subnet:     netip.MustParsePrefix("192.168.0.0/16"),
		},
		"ipv6_no_interface": {
			intf:       "",
			assignedIP: netip.MustParseAddr("fd00::2"),
			subnet:     netip.MustParsePrefix("fd00::/8"),
		},
		"remove": {
			intf:       "tun0",
			assignedIP: netip.MustParseAddr("10.8.0.2"),
			subnet:     netip.MustParsePrefix("192.168.0.0/16"),
			remove:     true,
		},
		"mixed_address_families": {
			intf:          "",
			assignedIP:    netip.MustParseAddr("10.8.0.2"),
			subnet:        netip.MustParsePrefix("fd00::/8"),
			expectedError: "source and destination address families do not match",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			if testCase.expectedError != "" {
				err := f.AcceptOutputFromIPToSubnet(t.Context(), testCase.intf,
					testCase.assignedIP, testCase.subnet, testCase.remove)
				assert.ErrorContains(t, err, testCase.expectedError)
				return
			}

			expectedExprs := expectedOutputSubnetExprs(testCase.intf,
				testCase.assignedIP, testCase.subnet)
			if testCase.remove {
				f.rules = []*nftables.Rule{{Exprs: expectedExprs}}
				expectExistingGluetunTable(mockConn)
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
					[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
				)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
			} else {
				expectNewGluetunTable(mockConn)
			}

			var addedRule *nftables.Rule
			if !testCase.remove {
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRule = rule
					return rule
				})
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptOutputFromIPToSubnet(t.Context(), testCase.intf,
				testCase.assignedIP, testCase.subnet, testCase.remove)

			assert.NoError(t, err)
			if !testCase.remove {
				assert.NotNil(t, addedRule)
				assert.Equal(t, outputChainName, addedRule.Chain.Name)
				assert.Equal(t, expectedExprs, addedRule.Exprs)
				assert.Len(t, f.rules, 1)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}

func Test_AcceptOutputThroughInterface(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		intf   string
		remove bool
	}{
		"named_interface": {intf: "tun0"},
		"empty_interface": {intf: ""},
		"all_interface":   {intf: "*"},
		"remove":          {intf: "tun0", remove: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			expectedExprs := expectedOutputIntfExprs(testCase.intf)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}
			if testCase.remove {
				f.rules = []*nftables.Rule{{Exprs: expectedExprs}}
				expectExistingGluetunTable(mockConn)
				mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).Return(
					[]*nftables.Rule{{Handle: 42, Exprs: expectedExprs}}, nil,
				)
				mockConn.EXPECT().DelRule(gomock.Any()).Return(nil)
			} else {
				expectNewGluetunTable(mockConn)
			}

			var addedRule *nftables.Rule
			if !testCase.remove {
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRule = rule
					return rule
				})
			}
			mockConn.EXPECT().Flush().Return(nil)

			err := f.AcceptOutputThroughInterface(t.Context(), testCase.intf, testCase.remove)

			assert.NoError(t, err)
			if !testCase.remove {
				assert.NotNil(t, addedRule)
				assert.Equal(t, outputChainName, addedRule.Chain.Name)
				assert.Equal(t, expectedExprs, addedRule.Exprs)
				assert.Len(t, f.rules, 1)
			} else {
				assert.Empty(t, f.rules)
			}
		})
	}
}
