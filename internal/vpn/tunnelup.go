package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/pmtud"
	pconstants "github.com/qdm12/gluetun/internal/pmtud/constants"
	"github.com/qdm12/gluetun/internal/pmtud/tcp"
	"github.com/qdm12/gluetun/internal/version"
	"github.com/qdm12/log"
)

type tunnelUpData struct {
	// Healthcheck
	serverIP netip.Addr
	pmtud    tunnelUpPMTUDData
	// Port forwarding
	vpnIntf        string
	serverName     string // used for PIA
	canPortForward bool   // used for PIA
	username       string // used for PIA
	password       string // used for PIA
	portForwarder  PortForwarder
}

type tunnelUpPMTUDData struct {
	// enabled is notably false if the user specifies a custom MTU.
	enabled bool
	// vpnType is used to find the maximum VPN header overhead.
	// It can be [vpn.Wireguard] or [vpn.OpenVPN].
	vpnType string
	// network is used to find the network level header overhead.
	// It can be [constants.UDP] or [constants.TCP].
	network string
	// icmpAddrs is the list of addresses to use for ICMP path MTU discovery.
	// Each address should handle ICMP packets for PMTUD to work.
	icmpAddrs []netip.Addr
	// tcpAddrs is the list of addresses to use for TCP path MTU discovery.
	// Each address should have a listening TCP server on the port specified.
	tcpAddrs []netip.AddrPort
}

func (l *Loop) onTunnelUp(ctx, loopCtx context.Context, data tunnelUpData) {
	l.client.CloseIdleConnections()

	for _, vpnPort := range l.vpnInputPorts {
		err := l.fw.SetAllowedPort(ctx, vpnPort, data.vpnIntf)
		if err != nil {
			l.logger.Error("cannot allow input port through firewall: " + err.Error())
		}
	}

	if data.pmtud.enabled {
		mtuLogger := l.logger.New(log.SetComponent("MTU discovery"))
		err := updateToMaxMTU(ctx, data.vpnIntf, data.pmtud.vpnType,
			data.pmtud.network, data.pmtud.icmpAddrs, data.pmtud.tcpAddrs,
			l.netLinker, l.routing, l.fw, mtuLogger)
		if err != nil {
			mtuLogger.Error(err.Error())
		}
	}

	icmpTargetIPs := l.healthSettings.ICMPTargetIPs
	if len(icmpTargetIPs) == 1 && icmpTargetIPs[0].IsUnspecified() {
		icmpTargetIPs = []netip.Addr{data.serverIP}
	}
	l.healthChecker.SetConfig(l.healthSettings.TargetAddresses, icmpTargetIPs,
		l.healthSettings.SmallCheckType, !*l.healthSettings.RestartVPN)

	healthErrCh, err := l.healthChecker.Start(ctx)
	l.healthServer.SetError(err)
	if err != nil {
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
	go l.collectHealthErrors(ctx, loopCtx, healthErrCh)

	_, _ = l.dnsLooper.ApplyStatus(ctx, constants.Running)

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

	_, err = l.boringPoll.Start()
	if err != nil {
		l.logger.Error("cannot start boring poll: " + err.Error())
	}
}

func (l *Loop) collectHealthErrors(ctx, loopCtx context.Context, healthErrCh <-chan error) {
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

func updateToMaxMTU(ctx context.Context, vpnInterface string,
	vpnType, network string, icmpAddrs []netip.Addr, tcpAddrs []netip.AddrPort,
	netlinker NetLinker, routing Routing, firewall tcp.Firewall, logger *log.Logger,
) error {
	logger.Info("finding maximum MTU, this can take up to 6 seconds")

	vpnGatewayIP, err := routing.VPNLocalGatewayIP(vpnInterface)
	if err != nil {
		return fmt.Errorf("getting VPN gateway IP address: %w", err)
	}

	vpnRoute, err := routing.VPNRoute(vpnInterface)
	if err != nil {
		return fmt.Errorf("getting VPN route: %w", err)
	}

	link, err := netlinker.LinkByName(vpnInterface)
	if err != nil {
		return fmt.Errorf("getting VPN interface by name: %w", err)
	}

	originalMTU := link.MTU

	vpnLinkMTU := pmtud.MaxTheoreticalVPNMTU(vpnType, network, vpnGatewayIP)

	// Setting the VPN link MTU to 1500 might interrupt the connection until
	// the new MTU is set again, but this is necessary to find the highest valid MTU.
	logger.Debugf("VPN interface %s MTU temporarily set to %d", vpnInterface, vpnLinkMTU)

	err = netlinker.LinkSetMTU(link.Index, vpnLinkMTU)
	if err != nil {
		return fmt.Errorf("setting VPN interface %s MTU to %d: %w", vpnInterface, vpnLinkMTU, err)
	}

	const pingTimeout = time.Second
	vpnLinkMTU, err = pmtud.PathMTUDiscover(ctx, icmpAddrs, tcpAddrs,
		vpnLinkMTU, pingTimeout, firewall, logger)
	if err != nil {
		vpnLinkMTU = originalMTU
		logger.Infof("reverting VPN interface %s MTU to %d (due to: %s)",
			vpnInterface, originalMTU, err)
	} else {
		logger.Infof("setting VPN interface %s MTU to maximum valid MTU %d", vpnInterface, vpnLinkMTU)
	}

	err = setTCPMSSOnVPNRoute(vpnLinkMTU, vpnRoute, netlinker)
	if err != nil {
		err = fmt.Errorf("setting safe TCP MSS for MTU %d: %w", vpnLinkMTU, err)
		vpnLinkMTU = originalMTU
		logger.Infof("reverting VPN interface %s MTU to %d (due to: %s)",
			vpnInterface, originalMTU, err)
	}

	err = netlinker.LinkSetMTU(link.Index, vpnLinkMTU)
	if err != nil {
		return fmt.Errorf("setting VPN interface %s MTU to %d: %w", vpnInterface, vpnLinkMTU, err)
	}

	return nil
}

func setTCPMSSOnVPNRoute(mtu uint32, route netlink.Route, netlinker NetLinker) error {
	ipHeaderLength := pconstants.IPv4HeaderLength
	if route.Dst.Addr().Is6() {
		ipHeaderLength = pconstants.IPv6HeaderLength
	}
	const mysteriousOverhead = 20 // most likely TCP options, such as the 12B of timestamps
	overhead := ipHeaderLength + pconstants.BaseTCPHeaderLength + mysteriousOverhead
	mss := mtu - overhead
	route.AdvMSS = mss
	return netlinker.RouteReplace(route)
}
