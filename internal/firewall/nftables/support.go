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

// IsSupported returns true if nftables is supported on the system, false otherwise.
func IsSupported() bool {
	conn, err := nftables.New()
	if err != nil {
		return false
	}
	_, err = conn.ListTable("filter")
	return err == nil
}

// Version obtains the version of the installed nftables.
func (f *Firewall) Version(ctx context.Context) (string, error) {
	const emptyVersionError = "nft version string is empty"
	cmd := exec.CommandContext(ctx, "nft", "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("running nft -v: %w", err)
	}
	outputStr := strings.TrimSpace(string(output))
	words := strings.Fields(outputStr)
	if len(words) == 0 {
		return "", errors.New(emptyVersionError)
	}
	return words[0], nil
}

// RunUserPostRules reads and executes custom nft commands from a file.
// Only lines starting with "nft" are executed. Lines starting with iptables
// commands are rejected with an error.
func (f *Firewall) RunUserPostRules(ctx context.Context, filepath string) error {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("opening user rules file: %w", err)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("reading user rules file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing user rules file: %w", err)
	}
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Only allow nft commands
		if !strings.HasPrefix(line, "nft") {
			f.logger.Warnf("line %d: skipping unrecognized command (expected nft): %s", lineNum+1, line)
			continue
		}

		// Ensure we're matching "nft" as a complete command prefix (not "nftables", "nftrace", etc.)
		if len(line) > 3 && line[3] != ' ' {
			f.logger.Warnf("line %d: skipping unrecognized command (expected nft): %s", lineNum+1, line)
			continue
		}

		// Extract nft arguments
		nftArgs := strings.TrimSpace(line[3:]) // Trim "nft" and leading space
		if nftArgs == "" {
			continue
		}

		args := strings.Fields(nftArgs)
		if len(args) == 0 {
			continue
		}

		cmd := exec.CommandContext(ctx, "nft", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := strings.TrimSpace(string(output))
			return fmt.Errorf("running user rule on line %d (nft %s): %w: %s",
				lineNum+1, nftArgs, err, outputStr)
		}
	}

	return nil
}
