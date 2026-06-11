//go:build !linux && !darwin

package tun

import (
	"fmt"
	"runtime"
)

func Setup() error {
	return fmt.Errorf("not implemented for %s", runtime.GOOS)
}
