package portforward

import (
	"context"
	"strings"
)

// errorContaining is a gomock matcher for a logged error containing the given
// substring. The loop wraps the errors it logs with the context of what it was
// doing, so tests assert on the part of the message they care about instead of
// repeating the wrapping layers of the production code.
type errorContaining struct {
	substring string
}

func (e errorContaining) Matches(x any) bool {
	message, ok := x.(string)
	return ok && strings.Contains(message, e.substring)
}

func (e errorContaining) String() string { return "contains " + e.substring }

// runningContext is a gomock matcher for a [context.Context] which is not over
// yet. The loop hands the context of its run to everything it starts, and the
// tests have no access to it, so they cannot name it: this checks the argument
// for what can be told of it, its type and that it is still alive, where
// gomock.Any lets any value through, dead context included.
type runningContext struct{}

func (runningContext) Matches(x any) bool {
	runCtx, ok := x.(context.Context)
	return ok && runCtx.Err() == nil
}

func (runningContext) String() string { return "a context which is not over" }
