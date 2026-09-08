//go:build linux || darwin

package command

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_start_real_command checks that no output line is lost when the
// command exits while its last output lines are still buffered in the pipe.
// cmd.Wait closes the pipe, so it must only be called after all the pipe
// reads are complete. Real commands are launched all at the same time to
// increase the probability of hitting the race condition.
func Test_start_real_command(t *testing.T) {
	t.Parallel()

	const (
		workers = 64
		lines   = 100
	)

	expectedLines := make([]string, lines)
	echoCommands := make([]string, lines)
	for i := range lines {
		expectedLines[i] = fmt.Sprint(i)
		echoCommands[i] = "echo " + expectedLines[i]
	}
	commandArgs := strings.Join(echoCommands, "; ")

	var lostLines atomic.Int64

	// Make all the workers start their command at the same time
	startCh := make(chan struct{})

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			<-startCh

			cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", commandArgs)
			stdoutLines, stderrLines, waitError, err := start(cmd)
			if err != nil {
				lostLines.Add(1)
				return
			}

			for _, expectedLine := range expectedLines {
				select {
				case line, ok := <-stdoutLines:
					if !ok || line != expectedLine {
						lostLines.Add(1)
						return
					}
				case <-stderrLines:
				}
			}

			assert.NoError(t, <-waitError)
		}()
	}
	close(startCh)
	wg.Wait()

	assert.Zero(t, lostLines.Load())
}
