package iptables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseChain(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		iptablesOutput string
		table          chain
		errMessage     string
	}{
		"no_output": {
			errMessage: "iptables chain list output is malformed: not enough lines to process in: ",
		},
		"single_line_only": {
			iptablesOutput: `Chain INPUT (policy ACCEPT 140K packets, 226M bytes)`,
			errMessage: "iptables chain list output is malformed: not enough lines to process in: " +
				"Chain INPUT (policy ACCEPT 140K packets, 226M bytes)",
		},
		"malformed_general_data_line": {
			iptablesOutput: `Chain INPUT
num pkts bytes target     prot opt in     out     source               destination`,
			errMessage: "parsing chain general data line: iptables chain list output is malformed: " +
				"expected 8 fields in \"Chain INPUT\"",
		},
		"malformed_legend": {
			iptablesOutput: `Chain INPUT (policy ACCEPT 140K packets, 226M bytes)
num pkts bytes target     prot opt in     out     source`,
			errMessage: "iptables chain list output is malformed: legend " +
				"\"num pkts bytes target     prot opt in     out     source\" " +
				"is not the expected \"num pkts bytes target prot opt in out source destination\"",
		},
		"no_rule": {
			iptablesOutput: `Chain INPUT (policy ACCEPT 140K packets, 226M bytes)
num pkts bytes target     prot opt in     out     source               destination`,
			table: chain{
				name:    "INPUT",
				policy:  "ACCEPT",
				packets: 140000,
				bytes:   226000000,
			},
		},
		"some_rules": {
			iptablesOutput: `Chain INPUT (policy ACCEPT 140K packets, 226M bytes)
num pkts bytes target     prot opt in     out     source               destination
1   0     0 ACCEPT     17   --  tun0   *       0.0.0.0/0            0.0.0.0/0            udp dpt:55405
2   0     0 ACCEPT     6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:55405
3   0     0 ACCEPT     1    --  tun0   *       0.0.0.0/0            0.0.0.0/0
4   0     0 DROP       0    --  tun0   *       1.2.3.4              0.0.0.0/0
5   0     0 ACCEPT     all  --  tun0   *       1.2.3.4              0.0.0.0/0
`,
			table: chain{
				name:    "INPUT",
				policy:  "ACCEPT",
				packets: 140000,
				bytes:   226000000,
				rules: []chainRule{
					{
						lineNumber:      1,
						packets:         0,
						bytes:           0,
						target:          "ACCEPT",
						protocol:        "udp",
						inputInterface:  "tun0",
						outputInterface: "*",
						source:          netip.MustParsePrefix("0.0.0.0/0"),
						destination:     netip.MustParsePrefix("0.0.0.0/0"),
						destinationPort: 55405,
					},
					{
						lineNumber:      2,
						packets:         0,
						bytes:           0,
						target:          "ACCEPT",
						protocol:        "tcp",
						inputInterface:  "tun0",
						outputInterface: "*",
						source:          netip.MustParsePrefix("0.0.0.0/0"),
						destination:     netip.MustParsePrefix("0.0.0.0/0"),
						destinationPort: 55405,
					},
					{
						lineNumber:      3,
						packets:         0,
						bytes:           0,
						target:          "ACCEPT",
						protocol:        "icmp",
						inputInterface:  "tun0",
						outputInterface: "*",
						source:          netip.MustParsePrefix("0.0.0.0/0"),
						destination:     netip.MustParsePrefix("0.0.0.0/0"),
					},
					{
						lineNumber:      4,
						packets:         0,
						bytes:           0,
						target:          "DROP",
						protocol:        "",
						inputInterface:  "tun0",
						outputInterface: "*",
						source:          netip.MustParsePrefix("1.2.3.4/32"),
						destination:     netip.MustParsePrefix("0.0.0.0/0"),
					},
					{
						lineNumber:      5,
						packets:         0,
						bytes:           0,
						target:          "ACCEPT",
						protocol:        "",
						inputInterface:  "tun0",
						outputInterface: "*",
						source:          netip.MustParsePrefix("1.2.3.4/32"),
						destination:     netip.MustParsePrefix("0.0.0.0/0"),
					},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			table, err := parseChain(testCase.iptablesOutput)

			assert.Equal(t, testCase.table, table)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
