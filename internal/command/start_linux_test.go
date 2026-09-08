//go:build linux

package command

import (
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_start_real_command checks that no output line is lost when the
// command exits while its last output line is still buffered in the pipe.
// cmd.Wait closes the pipe, so it must only be called after all the pipe
// reads are complete. Real commands are run in parallel to increase the
// probability of hitting the race condition.
func Test_start_real_command(t *testing.T) {
	t.Parallel()

	const workers = 64

	var lostLines atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "echo line")
			stdoutLines, stderrLines, waitError, err := start(cmd)
			if err != nil {
				lostLines.Add(1)
				return
			}

			seenLine := false
			stdoutClosed := false
			for !seenLine && !stdoutClosed {
				select {
				case line, ok := <-stdoutLines:
					stdoutClosed = !ok
					seenLine = ok && line == "line"
				case _, ok := <-stderrLines:
					_ = ok
				}
			}
			if !seenLine {
				lostLines.Add(1)
			}

			assert.NoError(t, <-waitError)
		}()
	}
	wg.Wait()

	assert.Zero(t, lostLines.Load())
}
