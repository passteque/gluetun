package wireguard

import (
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
)

func Test_makeDeviceLogger(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	logger := NewMockLogger(ctrl)

	deviceLogger := makeDeviceLogger(logger, false)

	logger.EXPECT().Debugf("test %d", 1)
	deviceLogger.Verbosef("test %d", 1)

	logger.EXPECT().Errorf("test %d", 2)
	deviceLogger.Errorf("test %d", 2)
}

func Test_makeDeviceLogger_gso_suggestion(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	logger := NewMockLogger(ctrl)

	deviceLogger := makeDeviceLogger(logger, true)

	const format = "Failed to write packets to TUN device: %v"
	writeError := errors.New("write /dev/net/tun: invalid argument")
	logger.EXPECT().Errorf(format, writeError).Times(2)
	logger.EXPECT().Warn("The kernel seems to reject GRO-coalesced writes to " +
		"the TUN device; consider setting WIREGUARD_GSO=off").Times(1)

	deviceLogger.Errorf(format, writeError)
	// The suggestion is only logged once for repeated errors.
	deviceLogger.Errorf(format, writeError)
}
