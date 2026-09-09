// Package tunstats offers a New function returning a Prometheus
// collector that exposes the cumulative number of bytes received and
// sent over the VPN network interface (TUN for OpenVPN, and the
// Wireguard interface for Wireguard and AmneziaWG). The interface name
// is resolved from the current VPN settings at each collection, and the
// byte counters are read from the sysfs statistics.
package tunstats

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
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

// Collector exposes the VPN network interface received and sent byte
// counters as Prometheus metrics.
type Collector struct {
	descRxBytes *prometheus.Desc
	descTxBytes *prometheus.Desc
	// getVPNSettings returns the current VPN settings.
	getVPNSettings func() settings.VPN
	// sysfsNetPath is the sysfs base path containing the network
	// interfaces. It defaults to /sys/class/net.
	sysfsNetPath string
}

// New creates a new VPN network interface byte counters Prometheus
// collector and registers it on the given registerer.
func New(registerer prometheus.Registerer, vpnLooper VPNLooper) (err error) {
	return newCollector(registerer, vpnLooper, defaultSysfsNetPath)
}

func newCollector(registerer prometheus.Registerer, vpnLooper VPNLooper,
	sysfsNetPath string,
) (err error) {
	collector := &Collector{
		descRxBytes: prometheus.NewDesc(metricRxBytesName, metricRxBytesHelp,
			[]string{labelInterface}, nil),
		descTxBytes: prometheus.NewDesc(metricTxBytesName, metricTxBytesHelp,
			[]string{labelInterface}, nil),
		getVPNSettings: vpnLooper.GetSettings,
		sysfsNetPath:   sysfsNetPath,
	}
	return registerer.Register(collector)
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descRxBytes
	ch <- c.descTxBytes
}

// Collect implements the prometheus.Collector interface. It emits
// nothing if the VPN network interface cannot be resolved, or its
// statistics cannot be read (for example when the VPN is not
// connected).
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	interfaceName := resolveInterfaceName(c.getVPNSettings())
	if interfaceName == "" {
		return
	}
	rxBytes, txBytes, err := c.readInterfaceStats(interfaceName)
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descRxBytes, prometheus.CounterValue,
		float64(rxBytes), interfaceName)
	ch <- prometheus.MustNewConstMetric(c.descTxBytes, prometheus.CounterValue,
		float64(txBytes), interfaceName)
}

// resolveInterfaceName returns the name of the VPN network interface
// from the given VPN settings, matching the interface actually used by
// the VPN. It returns the empty string if the VPN type is unknown, or
// the interface name is not set.
func resolveInterfaceName(vpnSettings settings.VPN) (interfaceName string) {
	switch vpnSettings.Type {
	case vpn.OpenVPN:
		interfaceName = vpnSettings.OpenVPN.Interface
	case vpn.Wireguard:
		interfaceName = vpnSettings.Wireguard.Interface
	case vpn.AmneziaWg:
		interfaceName = vpnSettings.AmneziaWg.Wireguard.Interface
	}
	return interfaceName
}
