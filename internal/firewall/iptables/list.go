package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type chain struct {
	name    string
	policy  string
	packets uint64
	bytes   uint64
	rules   []chainRule
}

type chainRule struct {
	lineNumber      uint16 // starts from 1 and cannot be zero.
	packets         uint64
	bytes           uint64
	target          string       // "ACCEPT", "DROP", "REJECT" or "REDIRECT"
	protocol        string       // "icmp", "tcp", "udp" or "" for all protocols.
	inputInterface  string       // input interface, for example "tun0" or "*""
	outputInterface string       // output interface, for example "eth0" or "*""
	source          netip.Prefix // source IP CIDR, for example 0.0.0.0/0. Must be valid.
	sourcePort      uint16       // Not specified if set to zero.
	destination     netip.Prefix // destination IP CIDR, for example 0.0.0.0/0. Must be valid.
	destinationPort uint16       // Not specified if set to zero.
	redirPorts      []uint16     // Not specified if empty.
	ctstate         []string     // for example ["RELATED","ESTABLISHED"]. Can be empty.
	tcpFlags        tcpFlags
	mark            mark
}

type mark struct {
	invert bool
	value  uint
}

func parseChain(iptablesOutput string) (c chain, err error) {
	// Text example:
	// Chain INPUT (policy ACCEPT 140K packets, 226M bytes)
	// pkts bytes target     prot opt in     out     source               destination
	// 	  0     0 ACCEPT     17   --  tun0   *       0.0.0.0/0            0.0.0.0/0            udp dpt:55405
	// 	  0     0 ACCEPT     6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:55405
	// 	  0     0 DROP       0    --  tun0   *       0.0.0.0/0            0.0.0.0/0
	iptablesOutput = strings.TrimSpace(iptablesOutput)
	linesWithComments := strings.Split(iptablesOutput, "\n")

	// Filter out lines starting with a '#' character
	lines := make([]string, 0, len(linesWithComments))
	for _, line := range linesWithComments {
		if strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}

	const minLines = 2 // chain general information line + legend line
	if len(lines) < minLines {
		return chain{}, fmt.Errorf("iptables chain list output is malformed: not enough lines to process in: %s",
			iptablesOutput)
	}

	c, err = parseChainGeneralDataLine(lines[0])
	if err != nil {
		return chain{}, fmt.Errorf("parsing chain general data line: %w", err)
	}

	// Sanity check for the legend line
	expectedLegendFields := []string{"num", "pkts", "bytes", "target", "prot", "opt", "in", "out", "source", "destination"}
	legendLine := strings.TrimSpace(lines[1])
	legendFields := strings.Fields(legendLine)
	if !slices.Equal(expectedLegendFields, legendFields) {
		return chain{}, fmt.Errorf("iptables chain list output is malformed: legend %q is not the expected %q",
			legendLine, strings.Join(expectedLegendFields, " "))
	}

	lines = lines[2:] // remove chain general information line and legend line
	if len(lines) == 0 {
		return c, nil
	}

	c.rules = make([]chainRule, len(lines))
	for i, line := range lines {
		c.rules[i], err = parseChainRuleLine(line)
		if err != nil {
			return chain{}, fmt.Errorf("parsing chain rule %q: %w", line, err)
		}
	}

	return c, nil
}

// parseChainGeneralDataLine parses the first line of iptables chain list output.
// For example, it can parse the following line:
// Chain INPUT (policy ACCEPT 140K packets, 226M bytes)
// It returns a chain struct with the parsed data.
func parseChainGeneralDataLine(line string) (base chain, err error) {
	line = strings.TrimSpace(line)
	runesToRemove := []rune{'(', ')', ','}
	for _, r := range runesToRemove {
		line = strings.ReplaceAll(line, string(r), "")
	}

	fields := strings.Fields(line)
	const expectedNumberOfFields = 8
	if len(fields) != expectedNumberOfFields {
		return chain{}, fmt.Errorf("iptables chain list output is malformed: expected %d fields in %q",
			expectedNumberOfFields, line)
	}

	// Sanity checks
	indexToExpectedValue := map[int]string{
		0: "Chain",
		2: "policy",
		5: "packets",
		7: "bytes",
	}
	for index, expectedValue := range indexToExpectedValue {
		if fields[index] == expectedValue {
			continue
		}
		return chain{}, fmt.Errorf("iptables chain list output is malformed: expected %q for field %d in %q",
			expectedValue, index, line)
	}

	base.name = fields[1] // chain name could be custom
	base.policy = fields[3]
	err = checkTarget(base.policy)
	if err != nil {
		return chain{}, fmt.Errorf("policy target in %q: %w", line, err)
	}

	packets, err := parseMetricSize(fields[4])
	if err != nil {
		return chain{}, fmt.Errorf("parsing packets: %w", err)
	}
	base.packets = packets

	bytes, err := parseMetricSize(fields[6])
	if err != nil {
		return chain{}, fmt.Errorf("parsing bytes: %w", err)
	}
	base.bytes = bytes

	return base, nil
}

func parseChainRuleLine(line string) (rule chainRule, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return chainRule{}, errors.New("chain rule is malformed: empty line")
	}

	fields := strings.Fields(line)

	const minFields = 10
	if len(fields) < minFields {
		return chainRule{}, errors.New("chain rule is malformed: not enough fields")
	}

	for fieldIndex, field := range fields[:minFields] {
		err = parseChainRuleField(fieldIndex, field, &rule)
		if err != nil {
			return chainRule{}, fmt.Errorf("parsing chain rule field: %w", err)
		}
	}

	if len(fields) > minFields {
		err = parseChainRuleOptionalFields(fields[minFields:], &rule)
		if err != nil {
			return chainRule{}, fmt.Errorf("parsing optional fields: %w", err)
		}
	}

	return rule, nil
}

func parseChainRuleField(fieldIndex int, field string, rule *chainRule) (err error) {
	if field == "" {
		return fmt.Errorf("chain rule is malformed: empty field at index %d", fieldIndex)
	}

	const (
		numIndex = iota
		packetsIndex
		bytesIndex
		targetIndex
		protocolIndex
		optIndex
		inputInterfaceIndex
		outputInterfaceIndex
		sourceIndex
		destinationIndex
	)

	switch fieldIndex {
	case numIndex:
		rule.lineNumber, err = parseLineNumber(field)
		if err != nil {
			return fmt.Errorf("parsing line number: %w", err)
		}
	case packetsIndex:
		rule.packets, err = parseMetricSize(field)
		if err != nil {
			return fmt.Errorf("parsing packets: %w", err)
		}
	case bytesIndex:
		rule.bytes, err = parseMetricSize(field)
		if err != nil {
			return fmt.Errorf("parsing bytes: %w", err)
		}
	case targetIndex:
		err = checkTarget(field)
		if err != nil {
			return fmt.Errorf("checking target: %w", err)
		}
		rule.target = field
	case protocolIndex:
		rule.protocol, err = parseProtocol(field)
		if err != nil {
			return fmt.Errorf("parsing protocol: %w", err)
		}
	case optIndex: // ignored
	case inputInterfaceIndex:
		rule.inputInterface = field
	case outputInterfaceIndex:
		rule.outputInterface = field
	case sourceIndex:
		rule.source, err = parseIPPrefix(field)
		if err != nil {
			return fmt.Errorf("parsing source IP CIDR: %w", err)
		}
	case destinationIndex:
		rule.destination, err = parseIPPrefix(field)
		if err != nil {
			return fmt.Errorf("parsing destination IP CIDR: %w", err)
		}
	}
	return nil
}

func parseChainRuleOptionalFields(optionalFields []string, rule *chainRule) (err error) {
	i := 0
	for i < len(optionalFields) {
		switch optionalFields[i] {
		case "udp":
			i++
			consumed, err := parseUDPOptional(optionalFields[i:], rule)
			if err != nil {
				return fmt.Errorf("parsing UDP optional fields: %w", err)
			}
			i += consumed
		case "tcp":
			i++
			consumed, err := parseTCPOptional(optionalFields[i:], rule)
			if err != nil {
				return fmt.Errorf("parsing TCP optional fields: %w", err)
			}
			i += consumed
		case "redir":
			i++
			switch optionalFields[i] {
			case "ports":
				i++
				ports, err := parsePortsCSV(optionalFields[i])
				if err != nil {
					return fmt.Errorf("parsing redirection ports: %w", err)
				}
				rule.redirPorts = ports
				i++
			default:
				return fmt.Errorf("chain rule is malformed: unexpected %q after redir",
					optionalFields[1])
			}
		case "ctstate":
			i++
			rule.ctstate = strings.Split(optionalFields[i], ",")
			i++
		case "mark":
			i++
			mark, consumed, err := parseMark(optionalFields[i:])
			if err != nil {
				return fmt.Errorf("parsing mark: %w", err)
			}
			rule.mark = mark
			i += consumed
		default:
			return fmt.Errorf("chain rule is malformed: unexpected optional field: %s",
				optionalFields[i])
		}
	}
	return nil
}

func parseUDPOptional(optionalFields []string, rule *chainRule) (consumed int, err error) {
	for _, value := range optionalFields {
		if !strings.ContainsRune(value, ':') {
			// no longer a UDP-associated option
			return consumed, nil
		}
		switch {
		case strings.HasPrefix(value, "dpt:"):
			rule.destinationPort, err = parseDestinationPort(value)
			if err != nil {
				return 0, fmt.Errorf("parsing destination port: %w", err)
			}
			consumed++
		case strings.HasPrefix(value, "spt:"):
			rule.sourcePort, err = parseSourcePort(value)
			if err != nil {
				return 0, fmt.Errorf("parsing source port: %w", err)
			}
			consumed++
		default:
			return 0, fmt.Errorf("unknown UDP optional field: %s", value)
		}
	}
	return consumed, nil
}

func parseTCPOptional(optionalFields []string, rule *chainRule) (consumed int, err error) {
	for _, value := range optionalFields {
		if !strings.ContainsRune(value, ':') {
			// no longer a TCP-associated option
			return consumed, nil
		}
		switch {
		case strings.HasPrefix(value, "dpt:"):
			rule.destinationPort, err = parseDestinationPort(value)
			if err != nil {
				return 0, fmt.Errorf("parsing destination port: %w", err)
			}
			consumed++
		case strings.HasPrefix(value, "spt:"):
			rule.sourcePort, err = parseSourcePort(value)
			if err != nil {
				return 0, fmt.Errorf("parsing source port: %w", err)
			}
			consumed++
		case strings.HasPrefix(value, "flags:"):
			rule.tcpFlags, err = parseTCPFlags(value)
			if err != nil {
				return 0, fmt.Errorf("parsing TCP flags: %w", err)
			}
			consumed++
		default:
			return 0, fmt.Errorf("unknown TCP optional field: %s", value)
		}
	}
	return consumed, nil
}

func parseDestinationPort(value string) (port uint16, err error) {
	value = strings.TrimPrefix(value, "dpt:")
	return parsePort(value)
}

func parseSourcePort(value string) (port uint16, err error) {
	value = strings.TrimPrefix(value, "spt:")
	return parsePort(value)
}

func parseTCPFlags(value string) (tcpFlags, error) {
	value = strings.TrimPrefix(value, "flags:")
	fields := strings.Split(value, "/")
	const expectedFields = 2
	if len(fields) != expectedFields {
		return tcpFlags{}, fmt.Errorf("TCP flags are malformed: expected format 'flags:<mask>/<comparison>' in %q",
			value)
	}
	maskFlags := strings.Split(fields[0], ",")
	mask := make([]tcpFlag, len(maskFlags))
	var err error
	for i, maskFlag := range maskFlags {
		mask[i], err = parseTCPFlag(maskFlag)
		if err != nil {
			return tcpFlags{}, fmt.Errorf("parsing TCP mask flags: %w", err)
		}
	}
	comparisonFlags := strings.Split(fields[1], ",")
	comparison := make([]tcpFlag, len(comparisonFlags))
	for i, comparisonFlag := range comparisonFlags {
		comparison[i], err = parseTCPFlag(comparisonFlag)
		if err != nil {
			return tcpFlags{}, fmt.Errorf("parsing TCP comparison flags: %w", err)
		}
	}
	return tcpFlags{
		mask:       mask,
		comparison: comparison,
	}, nil
}

func parsePortsCSV(s string) (ports []uint16, err error) {
	if s == "" {
		return nil, nil
	}

	fields := strings.Split(s, ",")
	ports = make([]uint16, len(fields))
	for i, field := range fields {
		ports[i], err = parsePort(field)
		if err != nil {
			return nil, err
		}
	}
	return ports, nil
}

func parseMark(optionalFields []string) (m mark, consumed int, err error) {
	switch optionalFields[consumed] {
	case "match":
		consumed++
		if optionalFields[consumed] == "!" {
			m.invert = true
			consumed++
		}

		const base = 0 // auto-detect
		const bits = 32
		value, err := strconv.ParseUint(optionalFields[consumed], base, bits)
		if err != nil {
			return mark{}, 0, fmt.Errorf("mark value is malformed: %s", optionalFields[consumed])
		}
		m.value = uint(value)
		consumed++
	default:
		return mark{}, 0, fmt.Errorf("chain rule is malformed: unexpected mark mode field: %s",
			optionalFields[consumed])
	}
	return m, consumed, nil
}

func parseLineNumber(s string) (n uint16, err error) {
	const base, bitLength = 10, 16
	lineNumber, err := strconv.ParseUint(s, base, bitLength)
	if err != nil {
		return 0, err
	} else if lineNumber == 0 {
		return 0, errors.New("line number is zero")
	}
	return uint16(lineNumber), nil
}

func checkTarget(target string) (err error) {
	switch target {
	case "ACCEPT", "DROP", "REJECT", "REDIRECT":
		return nil
	}
	return fmt.Errorf("unknown target: %s", target)
}

func parseProtocol(s string) (protocol string, err error) {
	switch s {
	case "0", "all":
	case "1", "icmp":
		protocol = "icmp"
	case "6", "tcp":
		protocol = "tcp"
	case "17", "udp":
		protocol = "udp"
	default:
		return "", fmt.Errorf("unknown protocol: %s", s)
	}
	return protocol, nil
}

// parseMetricSize parses a metric size string like 140K or 226M and
// returns the raw integer matching it.
func parseMetricSize(size string) (n uint64, err error) {
	if size == "" {
		return n, errors.New("metric size is malformed: empty string")
	}

	//nolint:mnd
	multiplerLetterToValue := map[byte]uint64{
		'K': 1000,
		'M': 1000000,
		'G': 1000000000,
		'T': 1000000000000,
	}

	lastCharacter := size[len(size)-1]
	multiplier, ok := multiplerLetterToValue[lastCharacter]
	if ok { // multiplier present
		size = size[:len(size)-1]
	} else {
		multiplier = 1
	}

	const base, bitLength = 10, 64
	n, err = strconv.ParseUint(size, base, bitLength)
	if err != nil {
		return n, fmt.Errorf("metric size is malformed: %w", err)
	}
	n *= multiplier
	return n, nil
}
