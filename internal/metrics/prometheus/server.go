// Package prometheus offers a New function returning a
// Prometheus HTTP server service to serve metrics.
package prometheus

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/goservices/httpserver"
)

// New creates a new Prometheus HTTP server service
// to serve metrics from the given gatherer
// on the listening address specified in the settings.
func New(settings settings.Prometheus, gatherer Gatherer,
	logger Logger,
) (server *httpserver.Server, err error) {
	handlerOptions := promhttp.HandlerOpts{
		ErrorLog: &promLogger{logger: logger},
	}
	httpSettings := httpserver.Settings{
		Name:    new("prometheus"),
		Handler: promhttp.HandlerFor(gatherer, handlerOptions),
		Address: new(settings.ListeningAddress),
		Logger:  logger,
	}
	return httpserver.New(httpSettings)
}
