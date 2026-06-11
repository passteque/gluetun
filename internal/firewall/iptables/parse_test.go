package iptables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseIptablesInstruction(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		s           string
		instruction iptablesInstruction
		errMessage  string
	}{
		"no_instruction": {
			errMessage: "iptables command is malformed: empty instruction",
		},
		"uneven_fields": {
			s:          "-A",
			errMessage: "parsing \"-A\": iptables command is malformed: flag \"-A\" requires a value, but got none",
		},
		"unknown_key": {
			s:          "-x something",
			errMessage: "parsing \"-x something\": iptables command is malformed: unknown key \"-x\"",
		},
		"one_pair": {
			s: "-A INPUT",
			instruction: iptablesInstruction{
				table:  "filter",
				chain:  "INPUT",
				append: true,
			},
		},
		"instruction_A": {
			s: "-A INPUT -i tun0 -p tcp -m tcp -s 1.2.3.4/32 -d 5.6.7.8 --dport 10000 -j ACCEPT",
			instruction: iptablesInstruction{
				table:           "filter",
				chain:           "INPUT",
				append:          true,
				inputInterface:  "tun0",
				protocol:        "tcp",
				source:          netip.MustParsePrefix("1.2.3.4/32"),
				destination:     netip.MustParsePrefix("5.6.7.8/32"),
				destinationPort: 10000,
				target:          "ACCEPT",
			},
		},
		"nat_redirection": {
			s: "-t nat --delete PREROUTING -i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678",
			instruction: iptablesInstruction{
				table:           "nat",
				chain:           "PREROUTING",
				append:          false,
				inputInterface:  "tun0",
				protocol:        "tcp",
				destinationPort: 43716,
				target:          "REDIRECT",
				toPorts:         []uint16{5678},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rule, err := parseIptablesInstruction(testCase.s)

			assert.Equal(t, testCase.instruction, rule)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_parseIPPrefix(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		value      string
		prefix     netip.Prefix
		errMessage string
	}{
		"empty": {
			errMessage: `parsing IP address: ParseAddr(""): unable to parse IP`,
		},
		"invalid": {
			value:      "invalid",
			errMessage: `parsing IP address: ParseAddr("invalid"): unable to parse IP`,
		},
		"valid_ipv4_with_bits": {
			value:  "10.0.0.0/16",
			prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), 16),
		},
		"valid_ipv4_without_bits": {
			value:  "10.0.0.4",
			prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 4}), 32),
		},
		"valid_ipv6_with_bits": {
			value: "2001:db8::/32",
			prefix: netip.PrefixFrom(
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8}),
				32),
		},
		"valid_ipv6_without_bits": {
			value: "2001:db8::",
			prefix: netip.PrefixFrom(
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8}),
				128),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prefix, err := parseIPPrefix(testCase.value)

			assert.Equal(t, testCase.prefix, prefix)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
