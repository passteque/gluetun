package iptables

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
)

var (
	ErrIPTablesVersionTooShort = errors.New("iptables version string is too short")
	ErrPolicyUnknown           = errors.New("unknown policy")
	ErrNeedIP6Tables           = errors.New("ip6tables is required, please upgrade your kernel to support it")
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
		return "", fmt.Errorf("%w: %s", ErrIPTablesVersionTooShort, output)
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
		return fmt.Errorf("command failed: \"%s %s\": %s: %w",
			c.ipTables, instruction, output, err)
	}
	return nil
}

func (c *Config) SetIPv4AllPolicies(ctx context.Context, policy string) error {
	switch policy {
	case "ACCEPT", "DROP":
	default:
		return fmt.Errorf("%w: %s", ErrPolicyUnknown, policy)
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
		return fmt.Errorf("accept input to subnet %s: %w", destination, ErrNeedIP6Tables)
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
		return fmt.Errorf("accept output to VPN server: %w", ErrNeedIP6Tables)
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
		return fmt.Errorf("accept output from %s to %s: %w", sourceIP, destinationSubnet, ErrNeedIP6Tables)
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
		restore(ctx) // just in case
		errMessage := err.Error()
		if strings.Contains(errMessage, "can't initialize ip6tables table `nat': Table does not exist") {
			if !remove {
				c.logger.Warn("IPv6 port redirection disabled because your kernel does not support IPv6 NAT: " + errMessage)
			}
			return nil
		}
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
			err = fmt.Errorf("running user ip6tables rule: %w", ErrNeedIP6Tables)
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
