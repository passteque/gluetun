package iptables

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// findIP6tablesSupported checks for multiple iptables implementations
// and returns the iptables path that is supported. If none work, an
// empty string path is returned.
func findIP6tablesSupported(ctx context.Context, runner CmdRunner) (
	ip6tablesPath string, err error,
) {
	ip6tablesPath, err = checkIptablesSupport(ctx, runner, "ip6tables", "ip6tables-legacy")
	if errors.Is(err, ErrNotSupported) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return ip6tablesPath, nil
}

func (c *Config) runIP6tablesInstructions(ctx context.Context, instructions []string) error {
	c.iptablesMutex.Lock() // only one iptables command at once
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestoreIPv6(ctx)
	if err != nil {
		return err
	}
	err = c.runIP6tablesInstructionsNoSave(ctx, instructions)
	if err != nil {
		restore(ctx)
	}
	return err
}

func (c *Config) runIP6tablesInstructionsNoSave(ctx context.Context, instructions []string) error {
	for _, instruction := range instructions {
		if err := c.runIP6tablesInstructionNoSave(ctx, instruction); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) runIP6tablesInstruction(ctx context.Context, instruction string) error {
	c.iptablesMutex.Lock() // only one iptables command at once
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestoreIPv6(ctx)
	if err != nil {
		return err
	}
	err = c.runIP6tablesInstructionNoSave(ctx, instruction)
	if err != nil {
		restore(ctx)
	}
	return err
}

func (c *Config) runIP6tablesInstructionNoSave(ctx context.Context, instruction string) error {
	if c.ip6Tables == "" {
		return nil
	}

	if isDeleteMatchInstruction(instruction) {
		return deleteIPTablesRule(ctx, c.ip6Tables, instruction,
			c.runner, c.logger)
	}

	flags := strings.Fields(instruction)
	cmd := exec.CommandContext(ctx, c.ip6Tables, flags...) // #nosec G204
	c.logger.Debug(cmd.String())
	if output, err := c.runner.Run(cmd); err != nil {
		return fmt.Errorf("command failed: \"%s %s\": %s: %w",
			c.ip6Tables, instruction, output, err)
	}
	return nil
}

var ErrPolicyNotValid = errors.New("policy is not valid")

func (c *Config) SetIPv6AllPolicies(ctx context.Context, policy string) error {
	switch policy {
	case "ACCEPT", "DROP":
	default:
		return fmt.Errorf("%w: %s", ErrPolicyNotValid, policy)
	}
	return c.runIP6tablesInstructions(ctx, []string{
		"--policy INPUT " + policy,
		"--policy OUTPUT " + policy,
		"--policy FORWARD " + policy,
	})
}
