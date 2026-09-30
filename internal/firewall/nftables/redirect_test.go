//go:build linux

package nftables

import (
	"encoding/binary"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func testPreroutingChain() *nftables.Chain {
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	return &nftables.Chain{
		Name: preroutingChainName, Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,
	}
}

func testGluetunChainsAll() []*nftables.Chain {
	return append(testBaseChainsAll(), testPreroutingChain())
}

// expected-value builders mirroring the production redirect rule composition.

func expectedPrerouteExprs(intf string, protocol uint8,
	sourcePort, destinationPort uint16,
) []expr.Any {
	destinationPortData := make([]byte, 2)
	binary.BigEndian.PutUint16(destinationPortData, destinationPort)
	exprs := append(inputInterfaceExprs(intf), protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(sourcePort)...)
	exprs = append(exprs,
		&expr.Immediate{Register: 1, Data: destinationPortData},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(nftables.TableFamilyINet),
			RegProtoMin: 1,
			RegProtoMax: 1,
			Specified:   true,
		},
	)
	return exprs
}

func expectedRedirectInputExprs(intf string, protocol uint8, destinationPort uint16) []expr.Any {
	exprs := append(inputInterfaceExprs(intf), protocolExprs(protocol)...)
	exprs = append(exprs, destinationPortExprs(destinationPort)...)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

func Test_buildRedirectPrerouteRule(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	preroutingChain := testPreroutingChain()
	sourcePort, destinationPort := uint16(12345), uint16(51820)

	testCases := map[string]struct {
		intf     string
		protocol uint8
	}{
		"udp_with_interface": {intf: "tun0", protocol: protocolUDP},
		"tcp_no_interface":   {intf: "", protocol: protocolTCP},
		"all_interface":      {intf: "*", protocol: protocolUDP},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rule := buildRedirectPrerouteRule(table, preroutingChain,
				testCase.intf, testCase.protocol, sourcePort, destinationPort)

			assert.Equal(t, table, rule.Table)
			assert.Equal(t, preroutingChain, rule.Chain)
			assert.Equal(t, expectedPrerouteExprs(testCase.intf, testCase.protocol,
				sourcePort, destinationPort), rule.Exprs)
		})
	}
}

func Test_buildRedirectInputRule(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	inputChain := &nftables.Chain{Name: inputChainName, Table: table}
	destinationPort := uint16(51820)

	testCases := map[string]struct {
		intf     string
		protocol uint8
	}{
		"udp_with_interface": {intf: "tun0", protocol: protocolUDP},
		"tcp_no_interface":   {intf: "", protocol: protocolTCP},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rule := buildRedirectInputRule(table, inputChain,
				testCase.intf, testCase.protocol, destinationPort)

			assert.Equal(t, table, rule.Table)
			assert.Equal(t, inputChain, rule.Chain)
			assert.Equal(t, expectedRedirectInputExprs(testCase.intf, testCase.protocol,
				destinationPort), rule.Exprs)
		})
	}
}

func Test_RedirectPort(t *testing.T) {
	t.Parallel()

	intf := "tun0"
	sourcePort, destinationPort := uint16(12345), uint16(51820)

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	preroutingChain := testPreroutingChain()
	inputChain := &nftables.Chain{Name: inputChainName, Table: table}

	// Pre-built tracked rules for the remove case (as they were added).
	buildTrackedRules := func() []*nftables.Rule {
		var rules []*nftables.Rule
		for _, protocol := range [2]uint8{protocolTCP, protocolUDP} {
			preroute := &nftables.Rule{
				Table: table, Chain: preroutingChain,
				Exprs: expectedPrerouteExprs(intf, protocol, sourcePort, destinationPort),
			}
			input := &nftables.Rule{
				Table: table, Chain: inputChain,
				Exprs: expectedRedirectInputExprs(intf, protocol, destinationPort),
			}
			rules = append(rules, preroute, input)
		}
		return rules
	}

	testCases := map[string]struct {
		remove bool
	}{
		"add_new_table":   {remove: false},
		"remove_existing": {remove: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

			if !testCase.remove {
				// Add path: create the table/4 chains, add 4 rules.
				mockConn.EXPECT().ListTables().Return(nil, nil)
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				}).Times(4)

				var addedRules []*nftables.Rule
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					addedRules = append(addedRules, rule)
					return rule
				}).Times(4)
				mockConn.EXPECT().Flush().Return(nil)

				err := f.RedirectPort(t.Context(), intf, sourcePort, destinationPort, false)

				assert.NoError(t, err)
				assert.Len(t, addedRules, 4)
				assert.Len(t, f.rules, 4)

				// Verify the 4 added rules (order: preroute, input per protocol).
				assert.Equal(t, expectedPrerouteExprs(intf, protocolTCP, sourcePort, destinationPort),
					addedRules[0].Exprs)
				assert.Equal(t, preroutingChainName, addedRules[0].Chain.Name)
				assert.Equal(t, expectedRedirectInputExprs(intf, protocolTCP, destinationPort),
					addedRules[1].Exprs)
				assert.Equal(t, inputChainName, addedRules[1].Chain.Name)
				assert.Equal(t, expectedPrerouteExprs(intf, protocolUDP, sourcePort, destinationPort),
					addedRules[2].Exprs)
				assert.Equal(t, expectedRedirectInputExprs(intf, protocolUDP, destinationPort),
					addedRules[3].Exprs)
				return
			}

			// Remove path: table/chains exist, delete 4 rules.
			f.rules = buildTrackedRules()
			mockConn.EXPECT().ListTables().Return(testGluetunTables(), nil)
			mockConn.EXPECT().ListChains().Return(testGluetunChainsAll(), nil).Times(2)

			mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).DoAndReturn(
				func(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
					var kernelRules []*nftables.Rule
					handle := uint64(1)
					for _, tracked := range f.rules {
						if tracked.Chain.Name == chain.Name {
							kernelRules = append(kernelRules, &nftables.Rule{
								Table: table, Chain: chain, Handle: handle, Exprs: tracked.Exprs,
							})
							handle++
						}
					}
					return kernelRules, nil
				},
			).Times(4)
			mockConn.EXPECT().DelRule(gomock.Any()).Return(nil).Times(4)
			mockConn.EXPECT().Flush().Return(nil)

			err := f.RedirectPort(t.Context(), intf, sourcePort, destinationPort, true)

			assert.NoError(t, err)
			assert.Empty(t, f.rules)
		})
	}
}
