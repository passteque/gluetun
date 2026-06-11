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

	streamDone := make(chan struct{})
	go streamLines(streamDone, logger, stdout, stderr)

	err = <-waitError
	<-streamDone
	return err
}

func streamLines(done chan<- struct{}, logger Logger,
	stdout, stderr <-chan string,
) {
	defer close(done)

	for {
		select {
		case line, ok := <-stdout:
			if ok {
				logger.Info(line)
			}
			if stderr == nil {
				return
			}
			stdout = nil
		case line, ok := <-stderr:
			if ok {
				logger.Error(line)
			}
			if stdout == nil {
				return
			}
			stderr = nil
		}
	}
}
