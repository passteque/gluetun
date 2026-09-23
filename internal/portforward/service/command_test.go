//go:build linux

package service

import (
	"context"
	"testing"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

func Test_Service_runCommand(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	ctx := context.Background()
	cmder := command.New()
	const commandTemplate = `/bin/sh -c "echo {{PORTS}}-{{PORT}}-{{VPN_INTERFACE}}"`
	ports := []uint16{1234, 5678}
	const vpnInterface = "tun0"
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("1234,5678-1234-tun0")

	err := runCommand(ctx, cmder, logger, commandTemplate, ports, vpnInterface)

	require.NoError(t, err)
}
