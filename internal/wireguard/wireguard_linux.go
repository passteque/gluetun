package wireguard

import (
	"net"
	"os"

	"golang.zx2c4.com/wireguard/ipc"
)

func UAPIOpen(name string) (*os.File, error) {
	return ipc.UAPIOpen(name)
}

func UAPIListen(interfaceName string, uapiFile *os.File) (net.Listener, error) {
	return ipc.UAPIListen(interfaceName, uapiFile)
}
