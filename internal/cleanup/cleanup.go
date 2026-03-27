package cleanup

import "sort"

type Cleanups []cleanup

type cleanup struct {
	operation  string
	orderIndex uint
	cleanup    func() error
	done       bool
}

// Add adds a cleanup function to the list of cleanups, with a description of the
// operation being cleaned up, and an order index that determines the order in which
// the cleanup functions are run. The lower the order index, the earlier the cleanup
// function is run.
func (c *Cleanups) Add(operation string, orderIndex uint,
	cleanupFunc func() error,
) {
	closer := cleanup{
		operation:  operation,
		orderIndex: orderIndex,
		cleanup:    cleanupFunc,
	}
	*c = append(*c, closer)
}

// Cleanup runs the cleanup functions in the order of their orderIndex,
// and logs any error that occurs during cleanup.
// It can also be re-called in case a cleanup fails, and already cleaned up
// functions will not be re-run.
func (c *Cleanups) Cleanup(logger Logger) {
	closers := *c

	sort.Slice(closers, func(i, j int) bool {
		return closers[i].orderIndex < closers[j].orderIndex
	})

	for i, closer := range closers {
		if closer.done {
			continue
		}
		closers[i].done = true
		logger.Debug(closer.operation + "...")
		err := closer.cleanup()
		if err != nil {
			logger.Error("failed " + closer.operation + ": " + err.Error())
		}
	}
}
