package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type operation uint8

const (
	opNone operation = iota
	opAppend
	opDelete
	opInsert
	opReplace
)

type iptablesInstruction struct {
	table           string // defaults to "filter", and can be "nat" for example.
	operation       operation
	chain           string       // for example INPUT, PREROUTING. Cannot be empty.
	target          string       // for example ACCEPT. Can be empty.
	protocol        string       // "tcp" or "udp" or "" for all protocols.
	inputInterface  string       // for example "tun0" or "" for any interface.
	outputInterface string       // for example "tun0" or "" for any interface.
	source          netip.Prefix // if not valid, then it is unspecified.
	sourcePort      uint16       // if zero, there is no source port
	destination     netip.Prefix // if not valid, then it is unspecified.
	destinationPort uint16       // if zero, there is no destination port
	toPorts         []uint16     // if empty, there is no redirection
	ctstate         []string     // if empty, there is no ctstate
	tcpFlags        tcpFlags
	mark            mark
	connMark        mark
	setMark         uint   // only used for jump CONNMARK --set-mark
	rejectWith      string // only used for REJECT targets
}

func (i *iptablesInstruction) setDefaults() {
	if i.table == "" {
		i.table = "filter"
	}
}

// equalToRule ignores the append boolean flag of the instruction to compare against the rule.
func (i *iptablesInstruction) equalToRule(table, chain string, rule chainRule) (equal bool) {
	switch {
	case i.table != table:
		return false
	case i.chain != chain:
		return false
	case i.target != rule.target:
		return false
	case i.protocol != rule.protocol:
		return false
	case i.destinationPort != rule.destinationPort:
		return false
	case i.sourcePort != rule.sourcePort:
		return false
	case !slices.Equal(i.toPorts, rule.redirPorts):
		return false
	case !slices.Equal(i.ctstate, rule.ctstate):
		return false
	case !networkInterfacesEqual(i.inputInterface, rule.inputInterface):
		return false
	case !networkInterfacesEqual(i.outputInterface, rule.outputInterface):
		return false
	case !ipPrefixesEqual(i.source, rule.source):
		return false
	case !ipPrefixesEqual(i.destination, rule.destination):
		return false
	case !slices.Equal(i.tcpFlags.mask, rule.tcpFlags.mask) ||
		!slices.Equal(i.tcpFlags.comparison, rule.tcpFlags.comparison):
		return false
	case i.mark != rule.mark:
		return false
	case i.connMark != rule.connMark:
		return false
	case i.setMark != rule.setMark:
		return false
	case i.rejectWith != rule.rejectWith:
		return false
	default:
		return true
	}
}

// instruction can be "" which equivalent to the "*" chain rule interface.
func networkInterfacesEqual(instruction, chainRule string) bool {
	return instruction == chainRule || (instruction == "" && chainRule == "*")
}

func ipPrefixesEqual(instruction, chainRule netip.Prefix) bool {
	return instruction == chainRule ||
		(!instruction.IsValid() && chainRule.Bits() == 0 && chainRule.Addr().IsUnspecified())
}

func parseIptablesInstruction(s string) (instruction iptablesInstruction, err error) {
	if s == "" {
		return iptablesInstruction{}, errors.New("iptables command is malformed: empty instruction")
	}
	fields := strings.Fields(s)

	i := 0
	for i < len(fields) {
		consumed, err := parseInstructionFlag(fields[i:], &instruction)
		if err != nil {
			return iptablesInstruction{}, fmt.Errorf("parsing %q: %w", s, err)
		}
		i += consumed
	}

	instruction.setDefaults()
	return instruction, nil
}

func parseInstructionFlag(fields []string, instruction *iptablesInstruction) (consumed int, err error) {
	consumed, err = preCheckInstructionFields(fields)
	if err != nil {
		return 0, err
	}
	flag := fields[0]
	value := fields[1]

	switch flag {
	case "-t", "--table":
		instruction.table = value
	case "-D", "--delete":
		instruction.operation = opDelete
		instruction.chain = value
	case "-A", "--append":
		instruction.operation = opAppend
		instruction.chain = value
	case "-I", "--insert":
		instruction.operation = opInsert
		instruction.chain = value
	case "-j", "--jump":
		subConsumed, err := parseJumpFlag(fields[1:], instruction)
		if err != nil {
			return 0, fmt.Errorf("parsing jump flag: %w", err)
		}
		consumed += subConsumed
	case "-p", "--protocol":
		instruction.protocol = value
	case "-m", "--match":
		consumed, err = parseMatchModule(fields, instruction)
		if err != nil {
			return 0, fmt.Errorf("parsing match module: %w", err)
		}
	case "--mark":
		n, err := parseAny32bNumber(value)
		if err != nil {
			return 0, fmt.Errorf("parsing mark value %q: %w", value, err)
		}
		instruction.mark.value = n
	case "-i", "--in-interface":
		instruction.inputInterface = value
	case "-o", "--out-interface":
		instruction.outputInterface = value
	case "-s", "--source":
		instruction.source, err = parseIPPrefix(value)
		if err != nil {
			return 0, fmt.Errorf("parsing source IP CIDR: %w", err)
		}
	case "--sport":
		instruction.sourcePort, err = parsePort(value)
		if err != nil {
			return 0, fmt.Errorf("parsing source port: %w", err)
		}
	case "-d", "--destination":
		instruction.destination, err = parseIPPrefix(value)
		if err != nil {
			return 0, fmt.Errorf("parsing destination IP CIDR: %w", err)
		}
	case "--dport":
		instruction.destinationPort, err = parsePort(value)
		if err != nil {
			return 0, fmt.Errorf("parsing destination port: %w", err)
		}
	case "--ctstate":
		instruction.ctstate = strings.Split(value, ",")
	case "--to-ports":
		instruction.toPorts, err = parseToPorts(value)
		if err != nil {
			return 0, fmt.Errorf("parsing port redirection: %w", err)
		}
	case "--tcp-flags":
		mask, comparison := value, fields[2]
		instruction.tcpFlags, err = parseTCPFlags(mask + "/" + comparison)
		if err != nil {
			return 0, fmt.Errorf("parsing TCP flags: %w", err)
		}
	case "--reject-with":
		instruction.rejectWith = value // for example "tcp-reset"
	default:
		return 0, fmt.Errorf("iptables command is malformed: unknown key %q", flag)
	}
	return consumed, nil
}

func preCheckInstructionFields(fields []string) (consumed int, err error) {
	flag := fields[0]
	// All flags use one value after the flag, except the following:
	switch flag {
	case "--tcp-flags":
		const expected = 3
		if len(fields) < expected {
			return 0, fmt.Errorf("iptables command is malformed: flag %q requires at least 2 values, but got %s",
				flag, strings.Join(fields, " "))
		}
		return expected, nil
	default:
		const expected = 2
		if len(fields) < expected {
			return 0, fmt.Errorf("iptables command is malformed: flag %q requires a value, but got none",
				flag)
		}
		return expected, nil
	}
}

func parseJumpFlag(fields []string, instruction *iptablesInstruction) (consumed int, err error) {
	instruction.target = fields[0]
	// consumed in the caller already takes fields[0] into account
	if instruction.target != "CONNMARK" {
		return consumed, nil
	}
	// consumed already accounts for the "CONNMARK" value
	const expectedFields = 3
	if len(fields) < expectedFields {
		return 0, fmt.Errorf("iptables command is malformed: jump CONNMARK requires at least two additional values")
	}
	switch fields[1] {
	case "--set-mark":
		n, err := parseAny32bNumber(fields[2])
		if err != nil {
			return 0, fmt.Errorf("parsing connmark mark value %q: %w", fields[2], err)
		}
		consumed++
		instruction.setMark = n
	default:
		return consumed, fmt.Errorf("iptables command is malformed: unsupported jump CONNMARK with value: %s",
			fields[1])
	}
	consumed++
	return consumed, nil
}

func parseIPPrefix(value string) (prefix netip.Prefix, err error) {
	slashIndex := strings.Index(value, "/")
	if slashIndex >= 0 {
		return netip.ParsePrefix(value)
	}

	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parsing IP address: %w", err)
	}
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func parsePort(value string) (port uint16, err error) {
	const base, bitLength = 10, 16
	portValue, err := strconv.ParseUint(value, base, bitLength)
	if err != nil {
		return 0, err
	}
	return uint16(portValue), nil
}

func parseAny32bNumber(mark string) (value uint, err error) {
	const base = 0 // auto-detect
	const bits = 32
	n, err := strconv.ParseUint(mark, base, bits)
	return uint(n), err
}

func parseMatchModule(fields []string, instruction *iptablesInstruction) (
	consumed int, err error,
) {
	_ = fields[consumed] // -m or --match flag already detected
	consumed++
	switch fields[consumed] {
	case "tcp", "udp", "conntrack":
		consumed++
		// for now ignore the protocol and conntrack matches since they are
		// auto-loaded when parsing the -p/--protocol and --ctstate flags,
		// and we don't need to parse them twice.
	case "mark":
		consumed++
		switch {
		case len(fields[consumed:]) == 0 || strings.HasPrefix(fields[consumed], "-"):
			// end or another flag
			return consumed, nil
		case fields[consumed] == "!":
			consumed++
			instruction.mark.invert = true
		default:
			return consumed, fmt.Errorf("iptables command is malformed: unsupported match mark with value: %s",
				fields[2])
		}
	case "connmark":
		consumed++
		if len(fields[consumed:]) > 0 && fields[consumed] == "!" {
			consumed++
			instruction.connMark.invert = true
		}
		switch {
		case len(fields[consumed:]) == 0:
			// end of rule, no mark value
			return consumed, nil
		case fields[consumed] == "--mark":
			consumed++
			if len(fields[consumed:]) == 0 {
				return consumed, fmt.Errorf("iptables command is malformed: connmark --mark requires a value")
			}
			n, err := parseAny32bNumber(fields[consumed])
			if err != nil {
				return consumed, fmt.Errorf("parsing connmark mark value %q: %w", fields[consumed], err)
			}
			instruction.connMark.value = n
			consumed++
		case strings.HasPrefix(fields[consumed], "-"):
			// another flag, no mark value
			return consumed, nil
		default:
			return consumed, fmt.Errorf("iptables command is malformed: unsupported match connmark with value: %s",
				fields[consumed])
		}
	default:
		return 0, fmt.Errorf("iptables command is malformed: unknown match value: %s",
			fields[consumed])
	}
	return consumed, nil
}

func parseToPorts(value string) (toPorts []uint16, err error) {
	portStrings := strings.Split(value, ",")
	toPorts = make([]uint16, len(portStrings))
	for i, portString := range portStrings {
		toPorts[i], err = parsePort(portString)
		if err != nil {
			return nil, err
		}
	}
	return toPorts, nil
}
