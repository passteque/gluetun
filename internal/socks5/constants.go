package socks5

import "fmt"

// See https://datatracker.ietf.org/doc/html/rfc1928#section-3
type authMethod byte

const (
	authNotRequired      authMethod = 0
	authGssapi           authMethod = 1
	authUsernamePassword authMethod = 2
	authNotAcceptable    authMethod = 255
)

func (a authMethod) String() string {
	switch a {
	case authNotRequired:
		return "no authentication required"
	case authGssapi:
		return "GSSAPI"
	case authUsernamePassword:
		return "username/password"
	case authNotAcceptable:
		return "no acceptable methods"
	default:
		return fmt.Sprintf("unknown method (%d)", a)
	}
}

// Subnegotiation version
// See https://datatracker.ietf.org/doc/html/rfc1929#section-2
const (
	authUsernamePasswordSubNegotiation1 byte = 1
)

// SOCKS versions.
const (
	socks5Version byte = 5
)

// See https://datatracker.ietf.org/doc/html/rfc1928#section-4
type cmdType byte

const (
	connect      cmdType = 1
	bind         cmdType = 2
	udpAssociate cmdType = 3
)

func (c cmdType) String() string {
	switch c {
	case connect:
		return "connect"
	case bind:
		return "bind"
	case udpAssociate:
		return "UDP associate"
	default:
		return fmt.Sprintf("unknown command (%d)", c)
	}
}

// See https://datatracker.ietf.org/doc/html/rfc1928#section-4 and
// https://datatracker.ietf.org/doc/html/rfc1928#section-5
type addrType byte

const (
	ipv4       addrType = 1
	domainName addrType = 3
	ipv6       addrType = 4
)

// See https://datatracker.ietf.org/doc/html/rfc1928#section-6
type replyCode byte

const (
	succeeded replyCode = iota
	generalServerFailure
	connectionNotAllowedByRuleset
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addressTypeNotSupported
)
