package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/qdm12/gluetun/devrun/internal"
)

func main() {
	const minArgs = 2
	if len(os.Args) < minArgs {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add-cred":
		const addCredMinArgs = 4
		if len(os.Args) < addCredMinArgs {
			fmt.Fprintf(os.Stderr,
				`Usage: %s add-cred <provider> <vpn-type>
Example: %s add-cred protonvpn wireguard`, os.Args[0], os.Args[0])
			os.Exit(1)
		}
		provider := os.Args[2]
		vpnType := os.Args[3]
		err := runWithSignals(func(ctx context.Context, _ <-chan struct{}) error {
			return internal.AddCredential(ctx, provider, vpnType)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "add-cred failed:", err)
			os.Exit(1)
		}
	case "delete-cred":
		const deleteCredMinArgs = 4
		if len(os.Args) < deleteCredMinArgs {
			fmt.Fprintf(os.Stderr,
				`Usage: %s delete-cred <provider> <vpn-type>
Example: %s delete-cred protonvpn openvpn`, os.Args[0], os.Args[0])
			os.Exit(1)
		}
		provider := os.Args[2]
		vpnType := os.Args[3]
		err := runWithSignals(func(ctx context.Context, _ <-chan struct{}) error {
			return internal.DeleteCredential(ctx, provider, vpnType)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "delete-cred failed:", err)
			os.Exit(1)
		}
	case "dump-cred":
		const dumpCredMinArgs = 4
		if len(os.Args) < dumpCredMinArgs {
			fmt.Fprintf(os.Stderr,
				`Usage: %s dump-cred <provider> <vpn-type>
Example: %s dump-cred protonvpn wireguard`, os.Args[0], os.Args[0])
			os.Exit(1)
		}
		provider := os.Args[2]
		vpnType := os.Args[3]
		err := runWithSignals(func(ctx context.Context, _ <-chan struct{}) error {
			return internal.DumpCredential(ctx, provider, vpnType)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "dump-cred failed:", err)
			os.Exit(1)
		}
	case "run":
		const runMinArgs = 4
		if len(os.Args) < runMinArgs {
			fmt.Fprintf(os.Stderr,
				`Usage: %s run <provider> <vpn-type> [extra docker flags...]
Example: %s run mullvad wireguard -e SERVER_COUNTRIES=USA`, os.Args[0], os.Args[0])
			os.Exit(1)
		}
		provider := os.Args[2]
		vpnType := os.Args[3]
		extraArgs := os.Args[4:]
		err := runWithSignals(func(ctx context.Context, forceKill <-chan struct{}) error {
			return internal.Run(ctx, provider, vpnType, extraArgs, forceKill)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "run failed:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s <command> [args...]

Commands:
	add-cred <provider> <vpn-type>
				Add or replace credentials in the encrypted credentials store.
	delete-cred <provider> <vpn-type>
				Delete credentials from the encrypted credentials store.
	dump-cred <provider> <vpn-type>
				Print credentials for a provider and VPN type pair.
	run <provider> <vpn-type> [flags...]
				Decrypt credentials and run a Gluetun container.
				Extra flags (e.g. -e PORT_FORWARDING=on) are passed to docker run.`,
		os.Args[0])
}

func runWithSignals(runFn func(ctx context.Context, forceKill <-chan struct{}) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const signalBufferSize = 3
	sigCh := make(chan os.Signal, signalBufferSize)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	forceKill := make(chan struct{})
	stopSignalLoop := make(chan struct{})
	signalLoopDone := make(chan struct{})

	go func() {
		defer close(signalLoopDone)

		const secondInterrupt = 2
		interruptCount := uint(0)
		forceKillSent := false
		for {
			select {
			case <-stopSignalLoop:
				return
			case <-sigCh:
				interruptCount++
				switch interruptCount {
				case 1:
					cancel()
				case secondInterrupt:
					if !forceKillSent {
						close(forceKill)
						forceKillSent = true
					}
				default:
					os.Exit(1)
				}
			}
		}
	}()

	err := runFn(ctx, forceKill)
	close(stopSignalLoop)
	<-signalLoopDone
	return err
}
