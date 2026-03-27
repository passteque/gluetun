package command

import (
	"context"
	"fmt"
	"os/exec"
)

func (c *Cmder) RunAndLog(ctx context.Context, command string, logger Logger) (err error) {
	args, err := split(command)
	if err != nil {
		return fmt.Errorf("parsing command: %w", err)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
	stdout, stderr, waitError, err := c.Start(cmd)
	if err != nil {
		return err
	}

	streamCtx, streamCancel := context.WithCancel(context.Background())
	streamDone := make(chan struct{})
	go streamLines(streamCtx, streamDone, logger, stdout, stderr)

	err = <-waitError
	streamCancel()
	<-streamDone
	return err
}

func streamLines(ctx context.Context, done chan<- struct{},
	logger Logger, stdout, stderr <-chan string,
) {
	defer close(done)

	var line string

	for {
		select {
		case <-ctx.Done():
			return
		case line = <-stdout:
			logger.Info(line)
		case line = <-stderr:
			logger.Error(line)
		}
	}
}
