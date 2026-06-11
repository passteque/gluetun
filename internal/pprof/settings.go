package pprof

import (
	"errors"
	"time"

	"github.com/qdm12/gluetun/internal/httpserver"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// Settings are the settings for the Pprof service.
type Settings struct {
	// Enabled can be false or true.
	// It defaults to false.
	Enabled *bool
	// See runtime.SetBlockProfileRate
	// Set to 0 to disable profiling.
	BlockProfileRate *int
	// See runtime.SetMutexProfileFraction
	// Set to 0 to disable profiling.
	MutexProfileRate *int
	// HTTPServer contains settings to configure
	// the HTTP server serving pprof data.
	HTTPServer httpserver.Settings
}

func (s *Settings) SetDefaults() {
	s.Enabled = gosettings.DefaultPointer(s.Enabled, false)
	s.HTTPServer.Address = gosettings.DefaultComparable(s.HTTPServer.Address, "localhost:6060")
	const defaultReadTimeout = 5 * time.Minute // for CPU profiling
	s.HTTPServer.ReadTimeout = gosettings.DefaultComparable(s.HTTPServer.ReadTimeout, defaultReadTimeout)
	s.HTTPServer.SetDefaults()
}

func (s Settings) Copy() (copied Settings) {
	return Settings{
		Enabled:          gosettings.CopyPointer(s.Enabled),
		BlockProfileRate: s.BlockProfileRate,
		MutexProfileRate: s.MutexProfileRate,
		HTTPServer:       s.HTTPServer.Copy(),
	}
}

func (s *Settings) OverrideWith(other Settings) {
	s.Enabled = gosettings.OverrideWithPointer(s.Enabled, other.Enabled)
	s.BlockProfileRate = gosettings.OverrideWithPointer(s.BlockProfileRate, other.BlockProfileRate)
	s.MutexProfileRate = gosettings.OverrideWithPointer(s.MutexProfileRate, other.MutexProfileRate)
	s.HTTPServer.OverrideWith(other.HTTPServer)
}

func (s Settings) Validate() (err error) {
	if *s.BlockProfileRate < 0 {
		return errors.New("block profile rate cannot be negative")
	}

	if *s.MutexProfileRate < 0 {
		return errors.New("mutex profile rate cannot be negative")
	}

	return s.HTTPServer.Validate()
}

func (s Settings) ToLinesNode() (node *gotree.Node) {
	if !*s.Enabled {
		return nil
	}

	node = gotree.New("Pprof settings:")

	if *s.BlockProfileRate > 0 {
		node.Appendf("Block profile rate: %d", *s.BlockProfileRate)
	}

	if *s.MutexProfileRate > 0 {
		node.Appendf("Mutex profile rate: %d", *s.MutexProfileRate)
	}

	node.AppendNode(s.HTTPServer.ToLinesNode())

	return node
}

func (s Settings) String() string {
	return s.ToLinesNode().String()
}

func (s *Settings) Read(r *reader.Reader) (err error) {
	s.Enabled, err = r.BoolPtr("PPROF_ENABLED")
	if err != nil {
		return err
	}

	s.BlockProfileRate, err = r.IntPtr("PPROF_BLOCK_PROFILE_RATE")
	if err != nil {
		return err
	}

	s.MutexProfileRate, err = r.IntPtr("PPROF_MUTEX_PROFILE_RATE")
	if err != nil {
		return err
	}

	s.HTTPServer.Address = r.String("PPROF_HTTP_SERVER_ADDRESS")

	return nil
}
