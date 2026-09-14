package customvpn

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/configuration/settings"
)

type Runner struct {
	settings  settings.CustomVPN
	starter   CmdStarter
	netLinker NetLinker
	logger    Logger
}

func NewRunner(settings settings.CustomVPN, starter CmdStarter,
	netLinker NetLinker, logger Logger,
) *Runner {
	return &Runner{
		settings:  settings,
		starter:   starter,
		netLinker: netLinker,
		logger:    logger,
	}
}

// Run starts the custom VPN binary and waits for it to exit.
// The binary is in charge of the whole tunnel setup: it must create
// its tunnel network interface and install the default route through
// it, since gluetun does no network setup for the custom VPN type.
func (r *Runner) Run(ctx context.Context, errCh chan<- error, ready chan<- struct{}) {
	var args []string
	if *r.settings.Args != "" {
		var err error
		args, err = command.Split(*r.settings.Args)
		if err != nil {
			errCh <- fmt.Errorf("splitting arguments: %w", err)
			return
		}
	}

	var readyLine *regexp.Regexp
	if *r.settings.ReadyLine != "" {
		var err error
		readyLine, err = regexp.Compile(*r.settings.ReadyLine)
		if err != nil {
			errCh <- fmt.Errorf("compiling ready line regular expression: %w", err)
			return
		}
	}

	// Running a user-defined binary is the purpose of the custom VPN type.
	cmd := exec.CommandContext(ctx, r.settings.Binary, args...) //nolint:gosec
	setCmdSysProcAttr(cmd)

	stdoutLines, stderrLines, waitError, err := r.starter.Start(cmd)
	if err != nil {
		errCh <- fmt.Errorf("starting binary: %w", err)
		return
	}

	readyCtx, readyCancel := context.WithCancel(ctx)
	defer readyCancel()

	streamDone := make(chan struct{})
	go streamLines(readyCtx, streamDone, r.logger,
		stdoutLines, stderrLines, readyLine, ready)

	if readyLine == nil {
		go r.pollTunnelReady(readyCtx, ready)
	}

	select {
	case <-ctx.Done():
		<-waitError
		<-streamDone
		errCh <- ctx.Err()
	case err := <-waitError:
		readyCancel()
		<-streamDone
		errCh <- err
	}
}
