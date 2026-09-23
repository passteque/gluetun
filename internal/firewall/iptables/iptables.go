package iptables

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

const (
	needIP6Tables = "ip6tables is required, please upgrade your kernel"
)

func appendOrDelete(remove bool) string {
	if remove {
		return "--delete"
	}
	return "--append"
}

// Version obtains the version of the installed iptables.
func (c *Config) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.ipTables, "--version") //nolint:gosec
	output, err := c.runner.Run(cmd)
	if err != nil {
		return "", err
	}
	words := strings.Fields(output)
	const minWords = 2
	if len(words) < minWords {
		return "", fmt.Errorf("iptables version string is too short: %s", output)
	}
	return "iptables " + words[1], nil
}

func (c *Config) runIptablesInstructions(ctx context.Context, instructions []string) error {
	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestoreIPv4(ctx)
	if err != nil {
		return err
	}

	err = c.runIptablesInstructionsNoSave(ctx, instructions)
	if err != nil {
		restore(ctx)
	}
	return err
}

func (c *Config) runIptablesInstructionsNoSave(ctx context.Context, instructions []string) error {
	for _, instruction := range instructions {
		if err := c.runIptablesInstructionNoSave(ctx, instruction); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) runIptablesInstruction(ctx context.Context, instruction string) error {
	c.iptablesMutex.Lock() // only one iptables command at once
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestoreIPv4(ctx)
	if err != nil {
		return err
	}

	err = c.runIptablesInstructionNoSave(ctx, instruction)
	if err != nil {
		restore(ctx)
	}
	return err
}

func (c *Config) runIptablesInstructionNoSave(ctx context.Context, instruction string) error {
	if isDeleteMatchInstruction(instruction) {
		return deleteIPTablesRule(ctx, c.ipTables, instruction,
			c.runner, c.logger)
	}

	flags := strings.Fields(instruction)
	cmd := exec.CommandContext(ctx, c.ipTables, flags...) // #nosec G204
	c.logger.Debug(cmd.String())
	if output, err := c.runner.Run(cmd); err != nil {
		if strings.Contains(output, "missing kernel module") {
			err = ErrKernelModuleMissing
		}
		return fmt.Errorf("command failed: \"%s %s\": %s: %w",
			c.ipTables, instruction, output, err)
	}
	return nil
}

func (c *Config) SetIPv4AllPolicies(ctx context.Context, policy string) error {
	switch policy {
	case "ACCEPT", "DROP":
	default:
		return fmt.Errorf("unknown policy: %s", policy)
	}
	return c.runIptablesInstructions(ctx, []string{
		"--policy INPUT " + policy,
		"--policy OUTPUT " + policy,
		"--policy FORWARD " + policy,
	})
}

func (c *Config) AcceptInputThroughInterface(ctx context.Context, intf string) error {
	return c.runMixedIptablesInstruction(ctx, fmt.Sprintf(
		"--append INPUT -i %s -j ACCEPT", intf))
}

func (c *Config) AcceptInputToSubnet(ctx context.Context, intf string, destination netip.Prefix) error {
	interfaceFlag := "-i " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}

	instruction := fmt.Sprintf("--append INPUT %s -d %s -j ACCEPT",
		interfaceFlag, destination.String())

	if destination.Addr().Is4() {
		return c.runIptablesInstruction(ctx, instruction)
	}
	if c.ip6Tables == "" {
		return fmt.Errorf("accept input to subnet %s: %s", destination, needIP6Tables)
	}
	return c.runIP6tablesInstruction(ctx, instruction)
}

func (c *Config) AcceptOutputThroughInterface(ctx context.Context, intf string, remove bool) error {
	return c.runMixedIptablesInstruction(ctx, fmt.Sprintf(
		"%s OUTPUT -o %s -j ACCEPT", appendOrDelete(remove), intf,
	))
}

func (c *Config) AcceptEstablishedRelatedTraffic(ctx context.Context) error {
	return c.runMixedIptablesInstructions(ctx, []string{
		"--append OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"--append INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	})
}

// publicOnlyChainName is the name of the custom iptables chain created by the
// public output traffic fallbacks. It is prefixed with GLUETUN to avoid
// clashing with a chain of the same name that a user or another application
// may have created.
const publicOnlyChainName = "GLUETUN_PUBLIC_ONLY"

// AcceptOutputPublicOnlyNewTraffic adds rules to mark new output connections, and to accept
// established or related packets with this mark only. This effectively forces
// previously established or related traffic to be blocked, which is used as a fallback
// to kill the existing connections when the conntrack tables cannot be flushed.
// The localPrefixes are added to the exceptions, so that existing connections to
// the local networks are not blocked.
func (c *Config) AcceptOutputPublicOnlyNewTraffic(ctx context.Context,
	localPrefixes []netip.Prefix,
) error {
	ipv4Instructions, ipv6Instructions := makeCreatePublicIPChainInstructions(localPrefixes)
	appendToBoth := func(instruction string) {
		ipv4Instructions = append(ipv4Instructions, instruction)
		ipv6Instructions = append(ipv6Instructions, instruction)
	}

	// Mark new connections with mark 0x567
	appendToBoth(fmt.Sprintf("-A %s -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x567",
		publicOnlyChainName))
	// Drop related/established connections that made it through; marked connections would
	// be directly accepted by the first rule in the OUTPUT chain (see below)
	appendToBoth(fmt.Sprintf("-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j DROP",
		publicOnlyChainName))
	// Set the chain as the second rule in the OUTPUT chain, so that it is evaluated
	// after the accept rule below, for performance reasons.
	appendToBoth("-I OUTPUT -j " + publicOnlyChainName)
	appendToBoth("-I OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -m connmark --mark 0x567 -j ACCEPT")

	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestore(ctx)
	if err != nil {
		return err
	}

	err = c.runIptablesInstructionsNoSave(ctx, ipv4Instructions)
	if err != nil {
		restore(ctx)
		return err
	}
	err = c.runIP6tablesInstructionsNoSave(ctx, ipv6Instructions)
	if err != nil {
		restore(ctx)
		return err
	}

	return nil
}

func (c *Config) RejectOutputPublicTraffic(ctx context.Context,
	localPrefixes []netip.Prefix, remove bool,
) error {
	return c.targetOutputPublicTraffic(ctx, "REJECT", localPrefixes, remove)
}

func (c *Config) DropOutputPublicTraffic(ctx context.Context,
	localPrefixes []netip.Prefix, remove bool,
) error {
	return c.targetOutputPublicTraffic(ctx, "DROP", localPrefixes, remove)
}

func (c *Config) targetOutputPublicTraffic(ctx context.Context,
	target string, localPrefixes []netip.Prefix, remove bool,
) error {
	removeInstructions := []string{
		"-D OUTPUT -j " + publicOnlyChainName,
		"-F " + publicOnlyChainName,
		"-X " + publicOnlyChainName,
	}
	if remove {
		return c.runMixedIptablesInstructions(ctx, removeInstructions)
	}

	ipv4Instructions, ipv6Instructions := makeCreatePublicIPChainInstructions(localPrefixes)
	appendToBoth := func(instruction string) {
		ipv4Instructions = append(ipv4Instructions, instruction)
		ipv6Instructions = append(ipv6Instructions, instruction)
	}

	if target == "REJECT" {
		// Block TCP by sending back TCP RST packets.
		appendToBoth(fmt.Sprintf("-A %s -p tcp -m conntrack --ctstate RELATED,ESTABLISHED "+
			"-j REJECT --reject-with tcp-reset", publicOnlyChainName))
		// Block UDP and ICMP, sending back ICMP port unreachable.
		appendToBoth(fmt.Sprintf("-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j REJECT",
			publicOnlyChainName))
	} else {
		appendToBoth(fmt.Sprintf("-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j %s",
			publicOnlyChainName, target))
	}
	appendToBoth("-I OUTPUT -j " + publicOnlyChainName)

	err := c.runIptablesInstructions(ctx, ipv4Instructions)
	if err != nil {
		if strings.Contains(err.Error(), " support") {
			return fmt.Errorf("%w: %w", ErrKernelModuleMissing, err)
		}
		return err
	}

	err = c.runIP6tablesInstructions(ctx, ipv6Instructions)
	if err != nil {
		_ = c.runIptablesInstructions(ctx, removeInstructions)
		if strings.Contains(err.Error(), " support") {
			return fmt.Errorf("%w: %w", ErrKernelModuleMissing, err)
		}
		return err
	}

	return nil
}

func makeCreatePublicIPChainInstructions(localPrefixes []netip.Prefix) (
	ipv4Instructions, ipv6Instructions []string,
) {
	ipv4PrivatePrefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
	}
	ipv6PrivatePrefixes := []netip.Prefix{
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("::1/128"),
	}

	// Add the configured local network prefixes to the exceptions, since
	// they can be globally routed (notably IPv6 local networks), and we
	// do not want to block the existing connections to them.
	for _, prefix := range localPrefixes {
		switch {
		case prefix.Addr().Is4() && !slices.Contains(ipv4PrivatePrefixes, prefix):
			ipv4PrivatePrefixes = append(ipv4PrivatePrefixes, prefix)
		case prefix.Addr().Is6() && !slices.Contains(ipv6PrivatePrefixes, prefix):
			ipv6PrivatePrefixes = append(ipv6PrivatePrefixes, prefix)
		}
	}

	ipv4Instructions = append(ipv4Instructions, "-N "+publicOnlyChainName)
	ipv6Instructions = append(ipv6Instructions, "-N "+publicOnlyChainName)

	for _, prefix := range ipv4PrivatePrefixes {
		ipv4Instructions = append(ipv4Instructions, fmt.Sprintf(
			"-A %s -d %s -j RETURN", publicOnlyChainName, prefix))
	}

	for _, prefix := range ipv6PrivatePrefixes {
		ipv6Instructions = append(ipv6Instructions, fmt.Sprintf(
			"-A %s -d %s -j RETURN", publicOnlyChainName, prefix))
	}

	return ipv4Instructions, ipv6Instructions
}

func (c *Config) AcceptOutputTrafficToVPN(ctx context.Context,
	defaultInterface string, connection models.Connection, remove bool,
) error {
	protocol := connection.Protocol
	instruction := fmt.Sprintf("%s OUTPUT -d %s -o %s -p %s -m %s --dport %d -j ACCEPT",
		appendOrDelete(remove), connection.IP, defaultInterface, protocol,
		protocol, connection.Port)
	if connection.IP.Is4() {
		return c.runIptablesInstruction(ctx, instruction)
	} else if c.ip6Tables == "" {
		return fmt.Errorf("accept output to VPN server %s: %s", connection.IP, needIP6Tables)
	}
	return c.runIP6tablesInstruction(ctx, instruction)
}

func (c *Config) AcceptOutput(ctx context.Context,
	protocol, intf string, ip netip.Addr, port uint16, remove bool,
) error {
	interfaceFlag := "-o " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}

	instruction := fmt.Sprintf("%s OUTPUT -d %s %s -p %s -m %s --dport %d -j ACCEPT",
		appendOrDelete(remove), ip, interfaceFlag, protocol, protocol, port)
	if ip.Is4() {
		return c.runIptablesInstruction(ctx, instruction)
	} else if c.ip6Tables == "" {
		return fmt.Errorf("accept output to VPN server %s: %s", ip, needIP6Tables)
	}
	return c.runIP6tablesInstruction(ctx, instruction)
}

func (c *Config) AcceptOutputFromIPPortToIPPort(ctx context.Context,
	protocol, intf string, source, destination netip.AddrPort, remove bool,
) error {
	if source.Addr().BitLen() != destination.Addr().BitLen() {
		return errors.New("source and destination address families do not match")
	}

	interfaceFlag := "-o " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}

	instruction := fmt.Sprintf("%s OUTPUT %s -s %s -d %s -p %s -m %s --sport %d --dport %d -j ACCEPT",
		appendOrDelete(remove), interfaceFlag, source.Addr(), destination.Addr(),
		protocol, protocol, source.Port(), destination.Port())
	if destination.Addr().Is4() {
		return c.runIptablesInstruction(ctx, instruction)
	} else if c.ip6Tables == "" {
		return fmt.Errorf("accept output from %s to %s: %s", source, destination, needIP6Tables)
	}
	return c.runIP6tablesInstruction(ctx, instruction)
}

// AcceptOutputFromIPToSubnet accepts outgoing traffic from sourceIP to destinationSubnet
// on the interface intf. If intf is empty, it is set to "*" which means all interfaces.
// If remove is true, the rule is removed instead of added.
// Thanks to @npawelek.
func (c *Config) AcceptOutputFromIPToSubnet(ctx context.Context,
	intf string, sourceIP netip.Addr, destinationSubnet netip.Prefix, remove bool,
) error {
	doIPv4 := sourceIP.Is4() && destinationSubnet.Addr().Is4()

	interfaceFlag := "-o " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}

	instruction := fmt.Sprintf("%s OUTPUT %s -s %s -d %s -j ACCEPT",
		appendOrDelete(remove), interfaceFlag, sourceIP.String(), destinationSubnet.String())

	if doIPv4 {
		return c.runIptablesInstruction(ctx, instruction)
	} else if c.ip6Tables == "" {
		return fmt.Errorf("accept output from %s to %s: %s", sourceIP, destinationSubnet, needIP6Tables)
	}
	return c.runIP6tablesInstruction(ctx, instruction)
}

// AcceptIpv6MulticastOutput accepts outgoing traffic to the IPv6 multicast address
// ff02::1:ff00:0/104, which is used for NDP (Neighbor Discovery Protocol) to resolve
// IPv6 addresses to MAC addresses. If intf is empty, it is set to "*" which means
// all interfaces. If remove is true, the rule is removed instead of added.
func (c *Config) AcceptIpv6MulticastOutput(ctx context.Context, intf string) error {
	interfaceFlag := "-o " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}
	instruction := fmt.Sprintf("--append OUTPUT %s -d ff02::1:ff00:0/104 -j ACCEPT", interfaceFlag)
	return c.runIP6tablesInstruction(ctx, instruction)
}

// AcceptInputToPort accepts incoming traffic on the specified port, for both TCP and UDP
// protocols, on the interface intf. If intf is empty, it is set to "*" which means all interfaces.
// If remove is true, the rule is removed instead of added. This is used for port forwarding, with
// intf set to the VPN tunnel interface.
func (c *Config) AcceptInputToPort(ctx context.Context, intf string, port uint16, remove bool) error {
	interfaceFlag := "-i " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}
	return c.runMixedIptablesInstructions(ctx, []string{
		fmt.Sprintf("%s INPUT %s -p tcp -m tcp --dport %d -j ACCEPT", appendOrDelete(remove), interfaceFlag, port),
		fmt.Sprintf("%s INPUT %s -p udp -m udp --dport %d -j ACCEPT", appendOrDelete(remove), interfaceFlag, port),
	})
}

// RedirectPort redirects incoming traffic on the specified source port to the
// specified destination port, for both TCP and UDP protocols, on the interface intf.
// If intf is empty, it is set to "*" which means all interfaces. If remove is true,
// the redirection is removed instead of added. This is used for VPN server side
// port forwarding, with intf set to the VPN tunnel interface.
func (c *Config) RedirectPort(ctx context.Context, intf string,
	sourcePort, destinationPort uint16, remove bool,
) (err error) {
	interfaceFlag := "-i " + intf
	if intf == "*" { // all interfaces
		interfaceFlag = ""
	}

	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestore(ctx)
	if err != nil {
		return err
	}

	err = c.runIptablesInstructionsNoSave(ctx, []string{
		fmt.Sprintf("-t nat %s PREROUTING %s -p tcp --dport %d -j REDIRECT --to-ports %d",
			appendOrDelete(remove), interfaceFlag, sourcePort, destinationPort),
		fmt.Sprintf("%s INPUT %s -p tcp -m tcp --dport %d -j ACCEPT",
			appendOrDelete(remove), interfaceFlag, destinationPort),
		fmt.Sprintf("-t nat %s PREROUTING %s -p udp --dport %d -j REDIRECT --to-ports %d",
			appendOrDelete(remove), interfaceFlag, sourcePort, destinationPort),
		fmt.Sprintf("%s INPUT %s -p udp -m udp --dport %d -j ACCEPT",
			appendOrDelete(remove), interfaceFlag, destinationPort),
	})
	if err != nil {
		restore(ctx)
		return fmt.Errorf("redirecting IPv4 source port %d to destination port %d on interface %s: %w",
			sourcePort, destinationPort, intf, err)
	}

	err = c.runIP6tablesInstructionsNoSave(ctx, []string{
		fmt.Sprintf("-t nat %s PREROUTING %s -p tcp --dport %d -j REDIRECT --to-ports %d",
			appendOrDelete(remove), interfaceFlag, sourcePort, destinationPort),
		fmt.Sprintf("%s INPUT %s -p tcp -m tcp --dport %d -j ACCEPT",
			appendOrDelete(remove), interfaceFlag, destinationPort),
		fmt.Sprintf("-t nat %s PREROUTING %s -p udp --dport %d -j REDIRECT --to-ports %d",
			appendOrDelete(remove), interfaceFlag, sourcePort, destinationPort),
		fmt.Sprintf("%s INPUT %s -p udp -m udp --dport %d -j ACCEPT",
			appendOrDelete(remove), interfaceFlag, destinationPort),
	})
	if err != nil {
		errMessage := err.Error()
		if strings.Contains(errMessage, "can't initialize ip6tables table `nat': Table does not exist") {
			if !remove {
				c.logger.Warn("IPv6 port redirection disabled because your kernel does not support IPv6 NAT: " + errMessage)
			}
			return nil
		}
		restore(ctx)
		return fmt.Errorf("redirecting IPv6 source port %d to destination port %d on interface %s: %w",
			sourcePort, destinationPort, intf, err)
	}
	return nil
}

func (c *Config) RunUserPostRules(ctx context.Context, filepath string) error {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	b, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestore(ctx)
	if err != nil {
		return err
	}

	for _, line := range lines {
		var ipv4 bool
		var rule string
		switch {
		case strings.HasPrefix(line, "iptables "):
			ipv4 = true
			rule = strings.TrimPrefix(line, "iptables ")
		case strings.HasPrefix(line, "iptables-nft "):
			ipv4 = true
			rule = strings.TrimPrefix(line, "iptables-nft ")
		case strings.HasPrefix(line, "iptables-legacy "):
			ipv4 = true
			rule = strings.TrimPrefix(line, "iptables-legacy ")
		case strings.HasPrefix(line, "ip6tables "):
			ipv4 = false
			rule = strings.TrimPrefix(line, "ip6tables ")
		case strings.HasPrefix(line, "ip6tables-nft "):
			ipv4 = false
			rule = strings.TrimPrefix(line, "ip6tables-nft ")
		case strings.HasPrefix(line, "ip6tables-legacy "):
			ipv4 = false
			rule = strings.TrimPrefix(line, "ip6tables-legacy ")
		default:
			continue
		}

		switch {
		case ipv4:
			err = c.runIptablesInstructionNoSave(ctx, rule)
		case c.ip6Tables == "":
			err = fmt.Errorf("running user ip6tables rule: %s", needIP6Tables)
		default: // ipv6
			err = c.runIP6tablesInstructionNoSave(ctx, rule)
		}
		if err != nil {
			restore(ctx)
			return err
		}
	}
	return nil
}
