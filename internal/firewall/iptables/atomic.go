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
	cmd := exec.CommandContext(ctx, c.ipTables+"-save") //nolint:gosec
	data, err := c.runner.Run(cmd)
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

	cmd := exec.CommandContext(ctx, c.ip6Tables+"-save") //nolint:gosec
	data, err := c.runner.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("saving IPv6 iptables: %w", err)
	}

	restore = func(ctx context.Context) {
		cmd = exec.CommandContext(ctx, c.ip6Tables+"-restore") //nolint:gosec
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
