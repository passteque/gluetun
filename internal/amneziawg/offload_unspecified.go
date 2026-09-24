//go:build !linux

package amneziawg

import (
	amneziatun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func createTUN(name string, mtu int, _ bool) (amneziatun.Device, error) { //nolint:ireturn
	return amneziatun.CreateTUN(name, mtu)
}
