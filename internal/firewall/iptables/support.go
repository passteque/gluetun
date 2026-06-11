package iptables

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"sort"
	"strings"
)

var ErrNotSupported = errors.New("no iptables supported found")

func checkIptablesSupport(ctx context.Context, runner CmdRunner,
	iptablesPathsToTry ...string,
) (iptablesPath string, err error) {
	iptablesPathToUnsupportedMessage := make(map[string]string, len(iptablesPathsToTry))
	for _, pathToTest := range iptablesPathsToTry {
		ok, unsupportedMessage, err := testIptablesPath(ctx, pathToTest, runner)
		if err != nil {
			return "", fmt.Errorf("for %s: %w", pathToTest, err)
		} else if ok {
			iptablesPath = pathToTest
			break
		}
		iptablesPathToUnsupportedMessage[pathToTest] = unsupportedMessage
	}

	if iptablesPath != "" {
		// some paths may be unsupported but that does not matter
		// since we found one working.
		return iptablesPath, nil
	}

	allArePermissionDenied := true
	allUnsupportedMessages := make(sort.StringSlice, 0, len(iptablesPathToUnsupportedMessage))
	for iptablesPath, unsupportedMessage := range iptablesPathToUnsupportedMessage {
		if !isPermissionDenied(unsupportedMessage) {
			allArePermissionDenied = false
		}
		unsupportedMessage = iptablesPath + ": " + unsupportedMessage
		allUnsupportedMessages = append(allUnsupportedMessages, unsupportedMessage)
	}

	allUnsupportedMessages.Sort() // predictable order for tests

	if allArePermissionDenied {
		// If the error is related to a denied permission for all iptables path,
		// return an error describing what to do from an end-user perspective.
		return "", fmt.Errorf("NET_ADMIN capability is missing: %s", strings.Join(allUnsupportedMessages, "; "))
	}

	return "", fmt.Errorf("%w: errors encountered are: %s",
		ErrNotSupported, strings.Join(allUnsupportedMessages, "; "))
}

func testIptablesPath(ctx context.Context, path string,
	runner CmdRunner) (ok bool, unsupportedMessage string,
	criticalErr error,
) {
	// Just listing iptables rules often work but we need
	// to modify them to ensure we can support the iptables
	// being tested.

	// Append a test rule with a random interface name to the OUTPUT table.
	// This should not affect existing rules or the network traffic.
	testInterfaceName := randomInterfaceName()
	cmd := exec.CommandContext(ctx, path,
		"-A", "OUTPUT", "-o", testInterfaceName, "-j", "DROP")
	output, err := runner.Run(cmd)
	if err != nil {
		unsupportedMessage = fmt.Sprintf("%s (%s)", output, err)
		return false, unsupportedMessage, nil
	}

	// Remove the random rule added previously for test.
	cmd = exec.CommandContext(ctx, path,
		"-D", "OUTPUT", "-o", testInterfaceName, "-j", "DROP")
	output, err = runner.Run(cmd)
	if err != nil {
		// this is a critical error, we want to make sure our test rule gets removed.
		criticalErr = fmt.Errorf("failed cleaning up test rule: %s (%s)", output, err)
		return false, "", criticalErr
	}

	// Set policy as the existing policy so no mutation is done.
	// This is an extra check for some buggy kernels where setting the policy
	// does not work.
	cmd = exec.CommandContext(ctx, path, "-nL", "INPUT")
	output, err = runner.Run(cmd)
	if err != nil {
		unsupportedMessage = fmt.Sprintf("%s (%s)", output, err)
		return false, unsupportedMessage, nil
	}

	var inputPolicy string
	for _, line := range strings.Split(output, "\n") {
		inputPolicy, ok = extractInputPolicy(line)
		if ok {
			break
		}
	}

	if inputPolicy == "" {
		criticalErr = fmt.Errorf("input policy not found: in INPUT rules: %s", output)
		return false, "", criticalErr
	}

	// Set the policy for the INPUT table to the existing policy found.
	cmd = exec.CommandContext(ctx, path, "--policy", "INPUT", inputPolicy)
	output, err = runner.Run(cmd)
	if err != nil {
		unsupportedMessage = fmt.Sprintf("%s (%s)", output, err)
		return false, unsupportedMessage, nil
	}

	return true, "", nil // success
}

func isPermissionDenied(errMessage string) (ok bool) {
	const permissionDeniedString = "Permission denied (you must be root)"
	return strings.Contains(errMessage, permissionDeniedString)
}

func extractInputPolicy(line string) (policy string, ok bool) {
	const prefixToFind = "Chain INPUT (policy "
	i := strings.Index(line, prefixToFind)
	if i == -1 {
		return "", false
	}

	startIndex := i + len(prefixToFind)
	endIndex := strings.Index(line, ")")
	if endIndex < 0 {
		return "", false
	}

	policy = line[startIndex:endIndex]
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return "", false
	}

	return policy, true
}

func randomInterfaceName() (interfaceName string) {
	const size = 15
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, size)
	for i := range b {
		letterIndex := rand.Intn(len(letterRunes)) //nolint:gosec
		b[i] = letterRunes[letterIndex]
	}
	return string(b)
}
