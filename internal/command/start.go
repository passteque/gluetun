package command

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
)

// Start launches a command and streams stdout and stderr to channels.
// stdoutLines and stderrLines channels will be closed when there is no more
// output to read, in order for the caller to catch all lines even after the
// command has finished. The waitError channel returned will never be closed.
func (c *Cmder) Start(cmd *exec.Cmd) (
	stdoutLines, stderrLines <-chan string,
	waitError <-chan error, startErr error,
) {
	return start(cmd)
}

func start(cmd execCmd) (stdoutLines, stderrLines <-chan string,
	waitError <-chan error, startErr error,
) {
	stdoutReady := make(chan struct{})
	stdoutLinesCh := make(chan string)
	stdoutDone := make(chan struct{})
	stderrReady := make(chan struct{})
	stderrLinesCh := make(chan string)
	stderrDone := make(chan struct{})

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	go streamToChannel(stdoutReady, stdoutDone, stdout, stdoutLinesCh)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		<-stdoutDone
		close(stdoutLinesCh)
		return nil, nil, nil, err
	}
	go streamToChannel(stderrReady, stderrDone, stderr, stderrLinesCh)

	err = cmd.Start()
	if err != nil {
		_ = stdout.Close()
		<-stdoutDone
		close(stdoutLinesCh)
		_ = stderr.Close()
		<-stderrDone
		close(stderrLinesCh)
		return nil, nil, nil, err
	}

	waitErrorCh := make(chan error)
	go func() {
		err := cmd.Wait()
		<-stdoutDone
		close(stdoutLinesCh)
		_ = stdout.Close()
		<-stderrDone
		close(stderrLinesCh)
		_ = stderr.Close()
		waitErrorCh <- err
	}()

	<-stdoutReady
	<-stderrReady

	return stdoutLinesCh, stderrLinesCh, waitErrorCh, nil
}

func streamToChannel(ready chan<- struct{}, done chan<- struct{},
	stream io.Reader, lines chan<- string,
) {
	defer close(done)
	close(ready)
	scanner := bufio.NewScanner(stream)
	lineBuffer := make([]byte, bufio.MaxScanTokenSize) // 64KB
	const maxCapacity = 20 * 1024 * 1024               // 20MB
	scanner.Buffer(lineBuffer, maxCapacity)

	for scanner.Scan() {
		// scanner is closed if the context is canceled
		// or if the command failed starting because the
		// stream is closed (io.EOF error).
		lines <- scanner.Text()
	}
	err := scanner.Err()
	if err == nil || errors.Is(err, os.ErrClosed) {
		return
	}
	lines <- "stream error: " + err.Error()
}
