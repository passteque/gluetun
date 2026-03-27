package iptables

import (
	"context"
)

func (c *Config) runMixedIptablesInstructions(ctx context.Context, instructions []string) error {
	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestore(ctx)
	if err != nil {
		return err
	}

	for _, instruction := range instructions {
		if err := c.runMixedIptablesInstructionNoSave(ctx, instruction); err != nil {
			restore(ctx)
			return err
		}
	}
	return nil
}

func (c *Config) runMixedIptablesInstruction(ctx context.Context, instruction string) error {
	c.iptablesMutex.Lock()
	defer c.iptablesMutex.Unlock()

	restore, err := c.saveAndRestore(ctx)
	if err != nil {
		return err
	}
	err = c.runMixedIptablesInstructionNoSave(ctx, instruction)
	if err != nil {
		restore(ctx)
	}
	return err
}

func (c *Config) runMixedIptablesInstructionNoSave(ctx context.Context, instruction string) error {
	if err := c.runIptablesInstructionNoSave(ctx, instruction); err != nil {
		return err
	}
	return c.runIP6tablesInstructionNoSave(ctx, instruction)
}
