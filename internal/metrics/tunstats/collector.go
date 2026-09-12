// Package tunstats offers a New function returning a Prometheus
// collector that exposes the cumulative number of bytes received and
// sent over the VPN network interface. The interface name is resolved
// from the current VPN settings at each collection, and the byte
// counters are read from the sysfs statistics.
package tunstats

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/netlink"
)

const (
	labelInterface = "interface"

	metricRxBytesName = "gluetun_tun_rx_bytes_total"
	metricRxBytesHelp = "Cumulative number of bytes received over the VPN network interface."

	metricTxBytesName = "gluetun_tun_tx_bytes_total"
	metricTxBytesHelp = "Cumulative number of bytes sent over the VPN network interface."
)

// VPNLooper is the interface to get the current VPN settings.
type VPNLooper interface {
	GetSettings() settings.VPN
}

// LinkLister is the interface to check whether a network link exists.
type LinkLister interface {
	LinkByName(name string) (link netlink.Link, err error)
}

// Logger is the interface to log warnings.
type Logger interface {
	Warn(message string)
}

// Collector exposes the VPN network interface received and sent byte
// counters as Prometheus metrics.
type Collector struct {
	descRxBytes *prometheus.Desc
	descTxBytes *prometheus.Desc
	// getVPNSettings returns the current VPN settings.
	getVPNSettings func() settings.VPN
	// linkLister checks whether the VPN network link exists.
	linkLister LinkLister
	// logger logs warnings.
	logger Logger
	// sysfsNetPath is the sysfs base path containing the network
	// interfaces.
	sysfsNetPath string
}

// New creates a new VPN network interface byte counters Prometheus
// collector and registers it on the given registerer.
func New(registerer prometheus.Registerer, vpnLooper VPNLooper,
	linkLister LinkLister, logger Logger,
) (err error) {
	const sysfsNetPath = "/sys/class/net"
	return newCollector(registerer, vpnLooper, linkLister, logger, sysfsNetPath)
}

func newCollector(registerer prometheus.Registerer, vpnLooper VPNLooper,
	linkLister LinkLister, logger Logger, sysfsNetPath string,
) (err error) {
	collector := &Collector{
		descRxBytes: prometheus.NewDesc(metricRxBytesName, metricRxBytesHelp,
			[]string{labelInterface}, nil),
		descTxBytes: prometheus.NewDesc(metricTxBytesName, metricTxBytesHelp,
			[]string{labelInterface}, nil),
		getVPNSettings: vpnLooper.GetSettings,
		linkLister:     linkLister,
		logger:         logger,
		sysfsNetPath:   sysfsNetPath,
	}
	return registerer.Register(collector)
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descRxBytes
	ch <- c.descTxBytes
}

// Collect implements the prometheus.Collector interface. It writes 0 to
// the metrics if the VPN network link does not exist (for example when
// the VPN is not connected, or is starting/restarting), and logs a
// warning if the link exists but its statistics cannot be read.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	interfaceName := resolveInterfaceName(c.getVPNSettings())

	_, err := c.linkLister.LinkByName(interfaceName)
	if err != nil {
		c.collectMetrics(ch, interfaceName, 0, 0)
		return
	}

	rxBytes, txBytes, err := c.readInterfaceStats(interfaceName)
	if err != nil {
		c.logger.Warn(fmt.Sprintf("reading interface statistics for %s: %s",
			interfaceName, err.Error()))
		return
	}

	c.collectMetrics(ch, interfaceName, rxBytes, txBytes)
}

func (c *Collector) collectMetrics(ch chan<- prometheus.Metric,
	interfaceName string, rxBytes, txBytes uint64,
) {
	ch <- prometheus.MustNewConstMetric(c.descRxBytes, prometheus.CounterValue,
		float64(rxBytes), interfaceName)
	ch <- prometheus.MustNewConstMetric(c.descTxBytes, prometheus.CounterValue,
		float64(txBytes), interfaceName)
}

// resolveInterfaceName returns the name of the VPN network interface
// from the given VPN settings, matching the interface actually used by
// the VPN.
func resolveInterfaceName(settings settings.VPN) (interfaceName string) {
	switch settings.Type {
	case vpn.OpenVPN:
		interfaceName = settings.OpenVPN.Interface
	case vpn.Wireguard:
		interfaceName = settings.Wireguard.Interface
	case vpn.AmneziaWg:
		interfaceName = settings.AmneziaWg.Wireguard.Interface
	default:
		panic("unknown VPN type: " + settings.Type)
	}
	return interfaceName
}
