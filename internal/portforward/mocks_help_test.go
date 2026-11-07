package portforward

import "strings"

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
