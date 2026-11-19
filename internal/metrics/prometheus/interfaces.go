package prometheus

import (
	dto "github.com/prometheus/client_model/go"
)

// Gatherer is the interface for the Prometheus gatherer
// to gather metrics.
type Gatherer interface {
	Gather() ([]*dto.MetricFamily, error)
}

// Logger is the logger interface accepted by the
// Prometheus HTTP server service.
type Logger interface {
	Info(s string)
	Error(s string)
}
