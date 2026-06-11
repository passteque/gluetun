package openvpn

import (
	"strings"
)

func streamLines(done chan<- struct{},
	logger Logger, stdout, stderr <-chan string,
	tunnelReady chan<- struct{},
) {
	defer close(done)

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
		line, level := processLogLine(line)
		if line == "" {
			continue // filtered out
		}
		if errLine {
			level = levelError
		}
		switch level {
		case levelInfo:
			logger.Info(line)
		case levelWarn:
			logger.Warn(line)
		case levelError:
			logger.Error(line)
		}
		if strings.Contains(line, "Initialization Sequence Completed") {
			// do not close tunnelReady in case the initialization
			// happens multiple times without Openvpn restarting
			tunnelReady <- struct{}{}
		}
	}
}
