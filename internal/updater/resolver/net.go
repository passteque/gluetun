package resolver

import (
	"net"
)

func newResolver(d Dialer) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial:     d.Dial,
	}
}
