package vpn

import (
	"context"
	"net/netip"

	"github.com/qdm12/dns/v2/pkg/check"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/version"
)

type tunnelUpData struct {
	// Healthcheck
	serverIP netip.Addr
	// Port forwarding
	vpnIntf        string
	serverName     string // used for PIA
	canPortForward bool   // used for PIA
	username       string // used for PIA
	password       string // used for PIA
	portForwarder  PortForwarder
}

func (l *Loop) onTunnelUp(ctx, loopCtx context.Context, data tunnelUpData) {
	l.client.CloseIdleConnections()

	for _, vpnPort := range l.vpnInputPorts {
		err := l.fw.SetAllowedPort(ctx, vpnPort, data.vpnIntf)
		if err != nil {
			l.logger.Error("cannot allow input port through firewall: " + err.Error())
		}
	}

	<-l.healthDone // make sure the health checker is stopped before restarting it
	icmpTargetIPs := l.healthSettings.ICMPTargetIPs
	if len(icmpTargetIPs) == 1 && icmpTargetIPs[0].IsUnspecified() {
		icmpTargetIPs = []netip.Addr{data.serverIP}
	}
	l.healthChecker.SetConfig(l.healthSettings.TargetAddresses, icmpTargetIPs,
		l.healthSettings.SmallCheckType, !*l.healthSettings.RestartVPN)

	healthErrCh, err := l.healthChecker.Start(ctx)
	l.healthServer.SetError(err)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if *l.healthSettings.RestartVPN {
			// Note this restart call must be done in a separate goroutine
			// from the VPN loop goroutine.
			l.restartVPN(loopCtx, err)
			return
		}
		l.logger.Warnf("(ignored) healthchecker start failed: %s", err)
		l.logger.Info("👉 See https://github.com/qdm12/gluetun-wiki/blob/main/faq/healthcheck.md")
	}

	// Start collecting health errors asynchronously, since
	// we should not wait for the code below to complete
	// to start monitoring health and auto-healing.
	// We keep track of when this goroutine is done with the healthDone
	// channel to avoid a race condition where the health checker is stopped
	// after being reconfigured and restarted, instead of before.
	healthDone := make(chan struct{})
	l.healthDone = healthDone
	go l.collectHealthErrors(ctx, loopCtx, healthDone, healthErrCh)

	if *l.dnsLooper.GetSettings().ServerEnabled {
		_, _ = l.dnsLooper.ApplyStatus(ctx, constants.Running)
	} else {
		err := check.WaitForDNS(ctx, check.Settings{})
		if err != nil {
			l.logger.Error("waiting for DNS to be ready: " + err.Error())
		}
	}

	err = l.publicip.RunOnce(ctx)
	if err != nil {
		l.logger.Error("getting public IP address information: " + err.Error())
	}

	if l.versionInfo {
		l.versionInfo = false // only get the version information once
		message, err := version.GetMessage(ctx, l.buildInfo, l.client)
		if err != nil {
			l.logger.Error("cannot get version information: " + err.Error())
		} else {
			l.logger.Info(message)
		}
	}

	err = l.startPortForwarding(data)
	if err != nil {
		l.logger.Error(err.Error())
	}
}

func (l *Loop) collectHealthErrors(ctx, loopCtx context.Context,
	done chan<- struct{}, healthErrCh <-chan error,
) {
	defer close(done)
	var previousHealthErr error
	for {
		select {
		case <-ctx.Done():
			_ = l.healthChecker.Stop()
			return
		case healthErr := <-healthErrCh:
			l.healthServer.SetError(healthErr)
			if healthErr != nil {
				if *l.healthSettings.RestartVPN {
					// Note this restart call must be done in a separate goroutine
					// from the VPN loop goroutine.
					_ = l.healthChecker.Stop()
					l.restartVPN(loopCtx, healthErr)
					return
				}
				l.logger.Warnf("(ignored) healthcheck failed: %s", healthErr)
				l.logger.Info("👉 See https://github.com/qdm12/gluetun-wiki/blob/main/faq/healthcheck.md")
			} else if previousHealthErr != nil {
				l.logger.Info("healthcheck passed successfully after previous failure(s)")
			}
			previousHealthErr = healthErr
		}
	}
}

func (l *Loop) restartVPN(ctx context.Context, healthErr error) {
	l.logger.Warnf("restarting VPN because it failed to pass the healthcheck: %s", healthErr)
	l.logger.Info("👉 See https://github.com/qdm12/gluetun-wiki/blob/main/faq/healthcheck.md")
	l.logger.Info("DO NOT OPEN AN ISSUE UNLESS YOU HAVE READ AND TRIED EVERY POSSIBLE SOLUTION")
	_, _ = l.ApplyStatus(ctx, constants.Stopped)
	_, _ = l.ApplyStatus(ctx, constants.Running)
}
