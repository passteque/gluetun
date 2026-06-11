package internal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func ptrTo[T any](v T) *T { return &v }

var (
	successRegexp        = regexp.MustCompile(`^.+Public IP address is .+$`)
	portForwardingRegexp = regexp.MustCompile(`port forwarded is \d`)
)

func runContainerTest(ctx context.Context, env []string,
	regexps []*regexp.Regexp, timeout time.Duration, logger Logger,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating Docker client: %w", err)
	}
	defer client.Close()

	config := &container.Config{
		Image:       "qmcgaw/gluetun",
		StopTimeout: ptrTo(3),
		Env:         env,
	}
	hostConfig := &container.HostConfig{
		AutoRemove: true,
		CapAdd:     []string{"NET_ADMIN", "NET_RAW"},
	}
	networkConfig := (*network.NetworkingConfig)(nil)
	platform := (*v1.Platform)(nil)
	const containerName = "" // auto-generated name

	response, err := client.ContainerCreate(ctx, config, hostConfig, networkConfig, platform, containerName)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	for _, warning := range response.Warnings {
		fmt.Println("Warning during container creation:", warning)
	}
	containerID := response.ID
	defer stopContainer(client, containerID)

	beforeStartTime := time.Now()

	err = client.ContainerStart(ctx, containerID, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	return waitForLogLines(ctx, client, containerID, beforeStartTime, regexps, logger)
}

func stopContainer(client *client.Client, containerID string) {
	const stopTimeout = 5 * time.Second // must be higher than 3s, see above [container.Config]'s StopTimeout field
	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopTimeout)
	defer stopCancel()

	err := client.ContainerStop(stopCtx, containerID, container.StopOptions{})
	if err != nil {
		fmt.Println("failed to stop container:", err)
	}
}

func waitForLogLines(ctx context.Context, client *client.Client, containerID string,
	beforeStartTime time.Time, regexps []*regexp.Regexp, logger Logger,
) error {
	logOptions := container.LogsOptions{
		ShowStdout: true,
		Follow:     true,
		Since:      beforeStartTime.Format(time.RFC3339Nano),
	}

	reader, err := client.ContainerLogs(ctx, containerID, logOptions)
	if err != nil {
		return fmt.Errorf("error getting container logs: %w", err)
	}
	defer reader.Close()

	regexpMatched := 0

	var linesSeen []string
	scanner := bufio.NewScanner(reader)
	for ctx.Err() == nil {
		if scanner.Scan() {
			line := scanner.Text()
			if len(line) > 8 { // remove Docker log prefix
				line = line[8:]
			}
			linesSeen = append(linesSeen, line)
			regex := regexps[regexpMatched]
			if regex.MatchString(line) {
				fmt.Println("✅ Expected line logged:", line)
				if regexpMatched == len(regexps)-1 {
					return nil
				}
				regexpMatched++
			}
			continue
		}
		err := scanner.Err()
		if err != nil && err != io.EOF {
			logSeenLines(linesSeen)
			return fmt.Errorf("reading log stream: %w", err)
		}

		// The scanner is either done or cannot read because of EOF
		logger.Info("the log scanner stopped")
		logSeenLines(linesSeen)

		// Check if the container is still running
		inspect, err := client.ContainerInspect(ctx, containerID)
		if err != nil {
			return fmt.Errorf("inspecting container: %w", err)
		}
		if !inspect.State.Running {
			return fmt.Errorf("container stopped unexpectedly while waiting for log line. Exit code: %d", inspect.State.ExitCode)
		}
	}

	return ctx.Err()
}

func logSeenLines(lines []string) {
	fmt.Println("Logs seen so far:")
	for _, line := range lines {
		fmt.Println("  " + line)
	}
}
