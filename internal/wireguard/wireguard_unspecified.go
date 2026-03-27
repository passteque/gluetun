//go:build !linux

package wireguard

import (
	"net"
	"os"
)

func UAPIOpen(name string) (*os.File, error) {
	panic("not implemented")
}

func UAPIListen(interfaceName string, uapiFile *os.File) (net.Listener, error) {
	panic("not implemented")
}
