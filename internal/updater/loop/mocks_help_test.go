package loop

import "context"

// liveContext is a gomock matcher for the context the loop hands over to an
// update, which is always live at the time of the call.
type liveContext struct{}

func (liveContext) Matches(x any) bool {
	ctx, ok := x.(context.Context)
	return ok && ctx.Err() == nil
}

func (liveContext) String() string { return "live context" }
