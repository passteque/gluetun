//go:build linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/google/nftables"
)

// IsSupported returns true if nftables is supported on the system, false
// otherwise.
func IsSupported() bool {
	conn, err := nftables.New()
	if err != nil {
		return false
	}

	_, err = conn.ListTables()
	return err == nil
}

// Version obtains the version of the installed nftables.
func (f *Firewall) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "nft", "--version")
	output, err := f.runner.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("running nft --version: %w", err)
	}

	version := strings.TrimSpace(output)
	if version == "" {
		return "", errors.New("nft version string is empty")
	}
	return version, nil
}

// RunUserPostRules reads and executes custom nft commands from a file. Only
// lines starting with "nft" followed by a space or tab are executed, other
// lines are skipped with a warning. The state of the rules is saved before
// execution and restored if any command fails.
func (f *Firewall) RunUserPostRules(ctx context.Context, filepath string) error {
	file, err := os.Open(filepath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("opening user rules file: %w", err)
	}
	defer func() { _ = file.Close() }()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("reading user rules file: %w", err)
	}

	rules := parseUserRules(content, f.logger)
	if len(rules) == 0 {
		return nil
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	conn, err := f.dialFunc()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	restore, err := f.saveAndRestoreLocked(conn)
	if err != nil {
		return fmt.Errorf("saving nftables state: %w", err)
	}

	for _, rule := range rules {
		cmd := exec.CommandContext(ctx, "nft", rule.args...) //nolint:gosec
		output, err := f.runner.Run(cmd)
		if err != nil {
			restore(ctx)
			return fmt.Errorf("running user rule on line %d (%s): %w: %s",
				rule.lineNum, rule.line, err, strings.TrimSpace(output))
		}
	}

	return nil
}

type userRule struct {
	lineNum int
	line    string
	args    []string
}

// parseUserRules parses the lines of a user rules file into the nft commands
// to execute. Lines that are not nft commands are skipped with a warning.
func parseUserRules(content []byte, logger Logger) []userRule {
	var rules []userRule
	for lineNum, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Only allow nft commands, "nft" being a complete command prefix
		// (not "nftables", "nftrace", etc.).
		if !strings.HasPrefix(line, "nft") ||
			(len(line) > 3 && line[3] != ' ' && line[3] != '\t') {
			logger.Warnf("line %d: skipping unrecognized command (expected nft): %s", lineNum+1, line)
			continue
		}

		// "nft" plus at least one argument.
		const minNftArgs = 2
		args := strings.Fields(line)
		if len(args) < minNftArgs {
			continue
		}
		rules = append(rules, userRule{lineNum: lineNum + 1, line: line, args: args[1:]})
	}
	return rules
}
