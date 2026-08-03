//go:build !linux

package wireguard

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

func createTUN(name string, mtu int, _ bool) (tun.Device, error) { //nolint:ireturn
	return tun.CreateTUN(name, mtu)
}

func OpenTUNFile(_ string) (*os.File, error) {
	panic("not implemented")
}
