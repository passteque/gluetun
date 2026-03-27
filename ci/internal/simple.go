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

func simpleTest(ctx context.Context, env []string, logger Logger) error {
	const timeout = 60 * time.Second
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

	return waitForLogLine(ctx, client, containerID, beforeStartTime, logger)
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

var successRegexp = regexp.MustCompile(`^.+Public IP address is .+$`)

func waitForLogLine(ctx context.Context, client *client.Client, containerID string,
	beforeStartTime time.Time, logger Logger,
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

	var linesSeen []string
	scanner := bufio.NewScanner(reader)
	for ctx.Err() == nil {
		if scanner.Scan() {
			line := scanner.Text()
			if len(line) > 8 { // remove Docker log prefix
				line = line[8:]
			}
			linesSeen = append(linesSeen, line)
			if successRegexp.MatchString(line) {
				fmt.Println("✅ Success line logged")
				return nil
			}
			continue
		}
		err := scanner.Err()
		if err != nil && err != io.EOF {
			logSeenLines(logger, linesSeen)
			return fmt.Errorf("reading log stream: %w", err)
		}

		// The scanner is either done or cannot read because of EOF
		logger.Info("the log scanner stopped")
		logSeenLines(logger, linesSeen)

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

func logSeenLines(logger Logger, lines []string) {
	fmt.Println("Logs seen so far:")
	for _, line := range lines {
		fmt.Println("  " + line)
	}
}
