package customvpn

import (
	"context"
	"regexp"
)

// streamLines logs each line the custom VPN binary writes to its
// standard output and standard error, until both streams are closed.
// If readyLine is not nil, the tunnelReady channel is signaled exactly
// once, on the first line matching the readyLine regular expression.
func streamLines(ctx context.Context, done chan<- struct{},
	logger Logger, stdout, stderr <-chan string,
	readyLine *regexp.Regexp, tunnelReady chan<- struct{},
) {
	defer close(done)

	readySignaled := false
	for {
		var line string
		var ok bool
		errLine := false
		select {
		case line, ok = <-stdout:
			if ok {
				break
			}
			if stderr == nil {
				return
			}
			stdout = nil
		case line, ok = <-stderr:
			if ok {
				errLine = true
				break
			}
			if stdout == nil {
				return
			}
			stderr = nil
		}
		if line == "" {
			continue
		}
		if errLine {
			logger.Error(line)
		} else {
			logger.Info(line)
		}
		if readySignaled || readyLine == nil || !readyLine.MatchString(line) {
			continue
		}
		readySignaled = true
		select {
		case tunnelReady <- struct{}{}:
		case <-ctx.Done():
		}
	}
}
