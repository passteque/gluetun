package iptables

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// SaveAndRestore saves the current iptables and ip6tables rules and
// returns a restore function that can be called to restore the saved rules.
func (c *Config) SaveAndRestore(ctx context.Context) (restore func(context.Context), err error) {
	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	return c.saveAndRestore(ctx)
}

// callers MUST always lock both the [Config] iptablesMutex and the ip6tablesMutex
// before calling this function. Note the restore function does not interact with mutexes
// so the caller must make sure the mutexes are locked when calling the restore function.
func (c *Config) saveAndRestore(ctx context.Context) (restore func(context.Context), err error) {
	restoreIPv4, err := c.saveAndRestoreIPv4(ctx)
	if err != nil {
		return nil, err
	}
	restoreIPv6, err := c.saveAndRestoreIPv6(ctx)
	if err != nil {
		return nil, err
	}

	restore = func(ctx context.Context) {
		restoreIPv4(ctx)
		if restoreIPv6 != nil {
			restoreIPv6(ctx)
		}
	}
	return restore, nil
}

// Callers of saveAndRestoreIPv4 MUST always lock the [Config] iptablesMutex
// before calling this function.
func (c *Config) saveAndRestoreIPv4(ctx context.Context) (restore func(context.Context), err error) {
	data, err := saveData(ctx, c.ipTables)
	if err != nil {
		return nil, fmt.Errorf("saving IPv4 iptables: %w", err)
	}

	restore = func(ctx context.Context) {
		cmd := exec.CommandContext(ctx, c.ipTables+"-restore") //nolint:gosec
		cmd.Stdin = strings.NewReader(data)
		output, err := c.runner.Run(cmd)
		if err != nil {
			c.logger.Warn(fmt.Sprintf("restoring IPv4 iptables failed: %s", makeRestoreErrorMessage(err, output, data)))
		}
	}
	return restore, nil
}

// Callers of saveAndRestoreIPv6 MUST always lock the [Config] ip6tablesMutex
// before calling this function.
func (c *Config) saveAndRestoreIPv6(ctx context.Context) (restore func(context.Context), err error) {
	if c.ip6Tables == "" {
		return nil, nil //nolint:nilnil
	}

	data, err := saveData(ctx, c.ip6Tables)
	if err != nil {
		return nil, fmt.Errorf("saving IPv6 iptables: %w", err)
	}

	restore = func(ctx context.Context) {
		cmd := exec.CommandContext(ctx, c.ip6Tables+"-restore") //nolint:gosec
		cmd.Stdin = strings.NewReader(data)
		output, err := c.runner.Run(cmd)
		if err != nil {
			c.logger.Warn(fmt.Sprintf("restoring IPv6 iptables failed: %s", makeRestoreErrorMessage(err, output, data)))
		}
	}
	return restore, nil
}

func makeRestoreErrorMessage(err error, output, data string) string {
	return fmt.Sprintf("%s: %s: restoring from data:\n%s", err, output, data)
}

func saveData(ctx context.Context, binary string) (data string, err error) {
	cmd := exec.CommandContext(ctx, binary+"-save") //nolint:gosec
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := strings.TrimSuffix(string(exitErr.Stderr), "\n")
			if stderr != "" {
				return "", fmt.Errorf("running %s-save: %w: %s", binary, err, stderr)
			}
		}
		return "", fmt.Errorf("running %s-save: %w", binary, err)
	}
	return filterData(output)
}

func filterData(cmdOutput []byte) (filtered string, err error) {
	lines := strings.Split(string(cmdOutput), "\n")
	filteredLines := make([]string, 0, len(lines))
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, ":DOCKER_OUTPUT"),
			strings.HasPrefix(line, ":DOCKER_POSTROUTING"),
			strings.HasPrefix(line, "-A DOCKER_OUTPUT"),
			strings.HasPrefix(line, "-A DOCKER_POSTROUTING"):
			// Do not touch (aka save and restore) NAT rules added by Docker
			continue
		case strings.Contains(line, "[unsupported revision]"):
			return "", fmt.Errorf("mismatch container iptables-save and kernel: %s", line)
		}
		filteredLines = append(filteredLines, line)
	}
	return strings.Join(filteredLines, "\n"), nil
}
