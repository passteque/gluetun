// Package metrics sets up metrics and creates a metrics service.
package metrics

import (
	"fmt"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/metrics/noop"
	"github.com/qdm12/gluetun/internal/metrics/prometheus"
	"github.com/qdm12/gluetun/internal/metrics/tunstats"
	"github.com/qdm12/goservices"
	"github.com/qdm12/log"
)

// ParentLogger is the interface to create a new logger
// for the metrics service.
type ParentLogger interface {
	New(options ...log.Option) *log.Logger
}

// New creates a new metrics service based on the
// metrics type in the settings. For the Prometheus type,
// it creates the metrics gatherer, on which the metrics
// collectors (such as the tunnel stats) are registered.
func New(settings settings.Metrics, parentLogger ParentLogger, //nolint:ireturn
	vpnLooper tunstats.VPNLooper, linkLister tunstats.LinkLister,
) (service goservices.Service, err error) {
	switch settings.Type {
	case "noop":
		return noop.New()
	case "prometheus":
		registry := promclient.NewRegistry()
		tunLogger := parentLogger.New(log.SetComponent("tunnel stats"))
		err = tunstats.New(registry, vpnLooper, linkLister, tunLogger)
		if err != nil {
			return nil, fmt.Errorf("registering tunnel stats collector: %w", err)
		}
		serverLogger := parentLogger.New(log.SetComponent("prometheus server"))
		return prometheus.New(settings.Prometheus, registry, serverLogger)
	default:
		panic("unknown metrics type: " + settings.Type)
	}
}
