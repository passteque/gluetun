package settings

import (
	"fmt"
	"os"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Metrics contains the settings for the metrics service.
type Metrics struct {
	// Type is the type of the metrics service to run.
	// It can be "prometheus" or "noop", and defaults to "noop".
	// It cannot be the empty string in the internal state.
	Type string
	// Prometheus contains the settings for the Prometheus metrics server.
	Prometheus Prometheus
}

func (m *Metrics) setDefaults() {
	const defaultType = "noop"
	m.Type = gosettings.DefaultComparable(m.Type, defaultType)
	m.Prometheus.setDefaults()
}

func (m Metrics) copy() (copied Metrics) {
	return Metrics{
		Type:       m.Type,
		Prometheus: m.Prometheus.copy(),
	}
}

func (m *Metrics) overrideWith(other Metrics) {
	m.Type = gosettings.OverrideWithComparable(m.Type, other.Type)
	m.Prometheus.overrideWith(other.Prometheus)
}

func (m Metrics) validate() (err error) {
	err = validate.IsOneOf(m.Type, "prometheus", "noop")
	if err != nil {
		return fmt.Errorf("type: %w", err)
	}

	err = m.Prometheus.validate()
	if err != nil {
		return fmt.Errorf("prometheus: %w", err)
	}

	return nil
}

func (m Metrics) String() string {
	return m.toLinesNode().String()
}

func (m Metrics) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Metrics settings:")
	node.Appendf("Type: %s", m.Type)
	switch m.Type {
	case "noop":
	case "prometheus":
		node.AppendNode(m.Prometheus.toLinesNode())
	default:
		panic("unknown metrics type: " + m.Type)
	}
	return node
}

func (m *Metrics) read(r *reader.Reader) (err error) {
	m.Type = r.String("METRICS_TYPE")
	m.Prometheus.read(r)
	return nil
}

// Prometheus contains the settings for the Prometheus metrics server.
type Prometheus struct {
	// ListeningAddress is the listening address for the Prometheus metrics HTTP server.
	// It cannot be the empty string in the internal state, and defaults to ":9090".
	ListeningAddress string
}

func (p *Prometheus) setDefaults() {
	const defaultListeningAddress = ":9090"
	p.ListeningAddress = gosettings.DefaultComparable(p.ListeningAddress, defaultListeningAddress)
}

func (p Prometheus) copy() (copied Prometheus) {
	return Prometheus{
		ListeningAddress: p.ListeningAddress,
	}
}

func (p *Prometheus) overrideWith(other Prometheus) {
	p.ListeningAddress = gosettings.OverrideWithComparable(p.ListeningAddress, other.ListeningAddress)
}

func (p Prometheus) validate() (err error) {
	err = validate.ListeningAddress(p.ListeningAddress, os.Getuid())
	if err != nil {
		return fmt.Errorf("listening address: %w", err)
	}
	return nil
}

func (p Prometheus) String() string {
	return p.toLinesNode().String()
}

func (p Prometheus) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Prometheus:")
	node.Appendf("Listening address: %s", p.ListeningAddress)
	return node
}

func (p *Prometheus) read(r *reader.Reader) {
	p.ListeningAddress = r.String("METRICS_PROMETHEUS_LISTENING_ADDRESS")
}
