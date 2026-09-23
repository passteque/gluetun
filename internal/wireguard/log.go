package wireguard

import (
	"fmt"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
)

//go:generate mockgen -destination=log_mock_test.go -package wireguard . Logger

type Logger interface {
	Debug(s string)
	Debugf(format string, args ...interface{})
	Info(s string)
	Warn(s string)
	Error(s string)
	Erroer
}

type Erroer interface {
	Errorf(format string, args ...any)
}

func makeDeviceLogger(logger Logger, gso bool) (deviceLogger *device.Logger) {
	errorf := logger.Errorf
	if gso {
		// Kernels advertising IFF_VNET_HDR support but rejecting
		// GRO-coalesced writes make wireguard-go log this error for
		// each failed write batch, see
		// https://github.com/tailscale/tailscale/issues/13041
		var suggestOnce sync.Once
		errorf = func(format string, args ...any) {
			logger.Errorf(format, args...)
			message := fmt.Sprintf(format, args...)
			if strings.Contains(message, "Failed to write packets to TUN device") &&
				strings.Contains(message, "invalid argument") {
				suggestOnce.Do(func() {
					logger.Warn("The kernel seems to reject GRO-coalesced writes to " +
						"the TUN device; consider setting WIREGUARD_GSO=off")
				})
			}
		}
	}
	return &device.Logger{
		Verbosef: logger.Debugf,
		Errorf:   errorf,
	}
}
