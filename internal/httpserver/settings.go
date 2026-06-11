package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type Settings struct {
	// Address is the server listening address.
	// It defaults to :8000.
	Address string
	// Handler is the HTTP Handler to use.
	// It must be set and cannot be left to nil.
	Handler http.Handler
	// Logger is the logger to use.
	// It must be set and cannot be left to nil.
	Logger Logger
	// ReadHeaderTimeout is the HTTP header read timeout duration
	// of the HTTP server. It defaults to 3 seconds if left unset.
	ReadHeaderTimeout time.Duration
	// ReadTimeout is the HTTP read timeout duration
	// of the HTTP server. It defaults to 3 seconds if left unset.
	ReadTimeout time.Duration
	// ShutdownTimeout is the shutdown timeout duration
	// of the HTTP server. It defaults to 3 seconds if left unset.
	ShutdownTimeout time.Duration
}

func (s *Settings) SetDefaults() {
	s.Address = gosettings.DefaultComparable(s.Address, ":8000")
	const defaultReadTimeout = 3 * time.Second
	s.ReadHeaderTimeout = gosettings.DefaultComparable(s.ReadHeaderTimeout, defaultReadTimeout)
	s.ReadTimeout = gosettings.DefaultComparable(s.ReadTimeout, defaultReadTimeout)
	const defaultShutdownTimeout = 3 * time.Second
	s.ShutdownTimeout = gosettings.DefaultComparable(s.ShutdownTimeout, defaultShutdownTimeout)
}

func (s Settings) Copy() Settings {
	return Settings{
		Address:           s.Address,
		Handler:           s.Handler,
		Logger:            s.Logger,
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		ReadTimeout:       s.ReadTimeout,
		ShutdownTimeout:   s.ShutdownTimeout,
	}
}

func (s *Settings) OverrideWith(other Settings) {
	s.Address = gosettings.OverrideWithComparable(s.Address, other.Address)
	s.Handler = gosettings.OverrideWithComparable(s.Handler, other.Handler)
	if other.Logger != nil {
		s.Logger = other.Logger
	}
	s.ReadHeaderTimeout = gosettings.OverrideWithComparable(s.ReadHeaderTimeout, other.ReadHeaderTimeout)
	s.ReadTimeout = gosettings.OverrideWithComparable(s.ReadTimeout, other.ReadTimeout)
	s.ShutdownTimeout = gosettings.OverrideWithComparable(s.ShutdownTimeout, other.ShutdownTimeout)
}

func (s Settings) Validate() (err error) {
	err = validate.ListeningAddress(s.Address, os.Getuid())
	if err != nil {
		return err
	}

	if s.Handler == nil {
		return errors.New("HTTP handler cannot be left unset")
	}

	if s.Logger == nil {
		return errors.New("logger cannot be left unset")
	}

	const minReadTimeout = time.Millisecond
	if s.ReadHeaderTimeout < minReadTimeout {
		return fmt.Errorf("read header timeout is too small: %s must be at least %s", s.ReadHeaderTimeout, minReadTimeout)
	}

	if s.ReadTimeout < minReadTimeout {
		return fmt.Errorf("read timeout is too small: %s must be at least %s", s.ReadTimeout, minReadTimeout)
	}

	const minShutdownTimeout = 5 * time.Millisecond
	if s.ShutdownTimeout < minShutdownTimeout {
		return fmt.Errorf("shutdown timeout is too small: %s must be at least %s", s.ShutdownTimeout, minShutdownTimeout)
	}

	return nil
}

func (s Settings) ToLinesNode() (node *gotree.Node) {
	node = gotree.New("HTTP server settings:")
	node.Appendf("Listening address: %s", s.Address)
	node.Appendf("Read header timeout: %s", s.ReadHeaderTimeout)
	node.Appendf("Read timeout: %s", s.ReadTimeout)
	node.Appendf("Shutdown timeout: %s", s.ShutdownTimeout)
	return node
}

func (s Settings) String() string {
	return s.ToLinesNode().String()
}
