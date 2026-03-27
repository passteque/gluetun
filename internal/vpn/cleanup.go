package vpn

import (
	"context"
	"errors"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func (l *Loop) cleanup() {
	settings := l.GetSettings()

	var err error
	if *settings.DownCommand != "" {
		commandString := strings.ReplaceAll(*settings.DownCommand, "{{VPN_INTERFACE}}", getVPNInterface(settings))
		err = l.cmder.RunAndLog(context.Background(), commandString, l.logger)
		if err != nil {
			l.logger.Error("failed to run VPN down command: " + err.Error())
		}
	}

	for _, vpnPort := range l.vpnInputPorts {
		err := l.fw.RemoveAllowedPort(context.Background(), vpnPort)
		if err != nil {
			l.logger.Error("cannot remove allowed input port from firewall: " + err.Error())
		}
	}

	err = l.publicip.ClearData()
	if err != nil {
		l.logger.Error("clearing public IP data: " + err.Error())
	}

	err = l.stopPortForwarding()
	if err != nil {
		portForwardingAlreadyStopped := errors.Is(err, context.Canceled)
		if !portForwardingAlreadyStopped {
			l.logger.Error("stopping port forwarding: " + err.Error())
		}
	}

	err = l.boringPoll.Stop()
	if err != nil {
		l.logger.Error("stopping boring poll: " + err.Error())
	}
}

func getVPNInterface(settings settings.VPN) string {
	switch settings.Type {
	case vpn.OpenVPN:
		return settings.OpenVPN.Interface
	case vpn.Wireguard:
		return settings.Wireguard.Interface
	default:
		panic("invalid VPN type: " + settings.Type)
	}
}
