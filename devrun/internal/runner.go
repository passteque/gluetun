package internal

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/term"
)

type containerOptions struct {
	env     []string
	binds   []string
	ports   nat.PortMap
	dns     []string
	devices []container.DeviceMapping
	labels  map[string]string
	capAdd  []string
}

// Run decrypts credentials, builds the container environment, and runs a Gluetun container.
// extraArgs is the list of additional flags (e.g. ["-e", "PORT_FORWARDING=on", "-v", "/host:/container"]).
func Run(ctx context.Context, provider, vpnType string, extraArgs []string,
	forceKill <-chan struct{},
) error {
	credentials, err := decryptCredentials(ctx)
	if err != nil {
		return fmt.Errorf("loading credentials: %w", err)
	}

	credentialEnvVars, err := lookupCredentials(credentials, provider, vpnType)
	if err != nil {
		return err
	}

	extraOpts, err := parseExtraArgs(extraArgs)
	if err != nil {
		return fmt.Errorf("parsing extra flags: %w", err)
	}
	opts := extraOpts
	opts.env = append(opts.env,
		"VPN_SERVICE_PROVIDER="+provider,
		"VPN_TYPE="+vpnType,
		"LOG_LEVEL=debug",
	)
	opts.env = append(opts.env, credentialEnvVars...)
	opts.capAdd = append(opts.capAdd, "NET_ADMIN")

	return runContainer(ctx, opts, forceKill)
}

// parseExtraArgs parses extra arguments and maps them to container options.
// Supported flags:
//
//	-e, --env KEY=VALUE       - environment variable
//	-v, --volume SPEC         - volume mount (e.g., "/host:/container" or "name:/container")
//	-p, --publish PORT:PORT   - port mapping
//	--dns IP                  - DNS server
//	--device SPEC             - device access (e.g., "/dev/net/tun")
//	--label KEY=VALUE         - container label
//	--cap-add CAPABILITY      - add Linux capability (e.g., "SYS_PTRACE")
func parseExtraArgs(args []string) (opts containerOptions, err error) { //nolint:gocognit,gocyclo
	opts = containerOptions{
		ports:  make(nat.PortMap),
		labels: make(map[string]string),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-e" || arg == "--env":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			opts.env = append(opts.env, args[i])
		case strings.HasPrefix(arg, "-e="):
			opts.env = append(opts.env, strings.TrimPrefix(arg, "-e="))
		case strings.HasPrefix(arg, "--env="):
			opts.env = append(opts.env, strings.TrimPrefix(arg, "--env="))

		case arg == "-v" || arg == "--volume":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			opts.binds = append(opts.binds, args[i])
		case strings.HasPrefix(arg, "-v="):
			opts.binds = append(opts.binds, strings.TrimPrefix(arg, "-v="))
		case strings.HasPrefix(arg, "--volume="):
			opts.binds = append(opts.binds, strings.TrimPrefix(arg, "--volume="))

		case arg == "-p" || arg == "--publish":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			if err := parsePortMapping(opts.ports, args[i]); err != nil {
				return opts, fmt.Errorf("parsing port mapping: %w", err)
			}
		case strings.HasPrefix(arg, "-p="):
			if err := parsePortMapping(opts.ports, strings.TrimPrefix(arg, "-p=")); err != nil {
				return opts, fmt.Errorf("parsing port mapping: %w", err)
			}
		case strings.HasPrefix(arg, "--publish="):
			if err := parsePortMapping(opts.ports, strings.TrimPrefix(arg, "--publish=")); err != nil {
				return opts, fmt.Errorf("parsing port mapping: %w", err)
			}

		case arg == "--dns":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			opts.dns = append(opts.dns, args[i])
		case strings.HasPrefix(arg, "--dns="):
			opts.dns = append(opts.dns, strings.TrimPrefix(arg, "--dns="))

		case arg == "--device":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			parseDeviceMapping(&opts.devices, args[i])
		case strings.HasPrefix(arg, "--device="):
			parseDeviceMapping(&opts.devices, strings.TrimPrefix(arg, "--device="))

		case arg == "--label":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			parseLabel(opts.labels, args[i])
		case strings.HasPrefix(arg, "--label="):
			parseLabel(opts.labels, strings.TrimPrefix(arg, "--label="))

		case arg == "--cap-add":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("flag %q requires an argument", arg)
			}
			i++
			opts.capAdd = append(opts.capAdd, args[i])
		case strings.HasPrefix(arg, "--cap-add="):
			opts.capAdd = append(opts.capAdd, strings.TrimPrefix(arg, "--cap-add="))

		default:
			return opts, fmt.Errorf("unsupported flag %q", arg)
		}
	}
	return opts, nil
}

func parsePortMapping(portMap nat.PortMap, spec string) error {
	port, bindings, err := nat.ParsePortSpecs([]string{spec})
	if err != nil {
		return err
	}
	for p, binding := range bindings {
		portMap[p] = binding
	}
	for p := range port {
		if _, exists := portMap[p]; !exists {
			portMap[p] = []nat.PortBinding{}
		}
	}
	return nil
}

func parseDeviceMapping(devices *[]container.DeviceMapping, spec string) {
	parts := strings.SplitN(spec, ":", 3) //nolint:mnd
	pathOnHost := parts[0]
	pathInContainer := pathOnHost
	permissions := "rwm"

	if len(parts) >= 2 { //nolint:mnd
		pathInContainer = parts[1]
	}
	if len(parts) >= 3 { //nolint:mnd
		permissions = parts[2]
	}

	*devices = append(*devices, container.DeviceMapping{
		PathOnHost:        pathOnHost,
		PathInContainer:   pathInContainer,
		CgroupPermissions: permissions,
	})
}

func parseLabel(labels map[string]string, kv string) {
	parts := strings.SplitN(kv, "=", 2) //nolint:mnd
	key := parts[0]
	value := ""
	if len(parts) > 1 {
		value = parts[1]
	}
	labels[key] = value
}

func runContainer(ctx context.Context, opts containerOptions, forceKill <-chan struct{}) error {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer dockerClient.Close()

	hasTTY := term.IsTerminal(int(os.Stdout.Fd()))

	containerConfig := &container.Config{
		Image:  "qmcgaw/gluetun",
		Env:    opts.env,
		Labels: opts.labels,
		Tty:    hasTTY,
	}

	mounts := make([]mount.Mount, 0, len(opts.binds))
	for _, bind := range opts.binds {
		m, err := parseBindMount(bind)
		if err != nil {
			return fmt.Errorf("parsing bind mount %q: %w", bind, err)
		}
		mounts = append(mounts, m)
	}

	hostConfig := &container.HostConfig{
		AutoRemove:   true,
		CapAdd:       opts.capAdd,
		Binds:        opts.binds,
		Mounts:       mounts,
		PortBindings: opts.ports,
		DNS:          opts.dns,
	}
	hostConfig.Devices = opts.devices

	networkConfig := &network.NetworkingConfig{}

	platform := (*v1.Platform)(nil)

	const containerName = "gluetun"
	response, err := dockerClient.ContainerCreate(ctx, containerConfig, hostConfig, networkConfig, platform, containerName)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	for _, warning := range response.Warnings {
		fmt.Fprintln(os.Stderr, "container creation warning:", warning)
	}
	containerID := response.ID

	err = dockerClient.ContainerStart(ctx, containerID, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("starting container: %w", err)
	}

	fmt.Printf("Container started (id: %.12s)\n", containerID)

	streamLogsErr := make(chan error, 1)
	go func() {
		streamLogsErr <- streamLogs(context.Background(), dockerClient, containerID, hasTTY)
	}()

	contextDone := ctx.Done()
	forceKillSignal := forceKill
	for {
		select {
		case err := <-streamLogsErr:
			if err != nil {
				return err
			}
			return nil
		case <-contextDone:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping container (5s timeout)...")
			err = stopContainer(dockerClient, containerID)
			if err != nil {
				fmt.Fprintln(os.Stderr, "stopping container:", err)
			}
			contextDone = nil
		case <-forceKillSignal:
			fmt.Fprintln(os.Stderr, "\nReceived second interrupt, killing container...")
			err = killContainer(dockerClient, containerID)
			if err != nil {
				fmt.Fprintln(os.Stderr, "killing container:", err)
			}
			forceKillSignal = nil
		}
	}
}

func parseBindMount(bind string) (mount.Mount, error) {
	parts := strings.SplitN(bind, ":", 3) //nolint:mnd
	if len(parts) < 2 {                   //nolint:mnd
		return mount.Mount{}, fmt.Errorf("invalid bind mount format: %q (expected source:target[:mode])", bind)
	}

	source := parts[0]
	target := parts[1]
	readOnly := len(parts) > 2 && strings.Contains(parts[2], "ro") //nolint:mnd

	return mount.Mount{
		Type:     mount.TypeBind,
		Source:   source,
		Target:   target,
		ReadOnly: readOnly,
	}, nil
}

func stopContainer(dockerClient *client.Client, containerID string) error {
	const stopTimeout = 5 * time.Second
	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopTimeout)
	defer stopCancel()
	timeoutSeconds := int(stopTimeout.Seconds())
	return dockerClient.ContainerStop(stopCtx, containerID, container.StopOptions{Timeout: &timeoutSeconds})
}

func killContainer(dockerClient *client.Client, containerID string) error {
	return dockerClient.ContainerKill(context.Background(), containerID, "KILL")
}

func streamLogs(ctx context.Context, dockerClient *client.Client, containerID string, hasTTY bool) error {
	logOptions := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: false,
	}

	reader, err := dockerClient.ContainerLogs(ctx, containerID, logOptions)
	if err != nil {
		return fmt.Errorf("getting container logs: %w", err)
	}
	defer reader.Close()

	if hasTTY {
		_, err = io.Copy(os.Stdout, reader)
	} else {
		_, err = stdcopy.StdCopy(os.Stdout, os.Stderr, reader)
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("streaming container logs: %w", err)
	}

	return nil
}
