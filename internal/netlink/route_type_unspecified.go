//go:build !linux

package netlink

// Route types values that can never match on non-Linux platforms,
// see route_type_linux.go for the Linux values.
const (
	routeTypeUnreachable uint8 = 253
	routeTypeProhibit    uint8 = 254
	routeTypeBlackhole   uint8 = 255
)
