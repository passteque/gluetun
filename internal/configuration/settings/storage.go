package settings

import (
	"fmt"
	"path/filepath"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// Storage contains settings to configure the storage.
type Storage struct {
	// ServersEnabled is whether to enable storage of servers on disk.
	// It defaults to true.
	ServersEnabled *bool
	// ServersPath is the path to the servers files directory, and cannot be
	// the empty string.
	ServersPath string
	// LegacyServersFilepath is the legacy "fat" JSON filepath to migrate from.
	// TODO v4: remove
	LegacyServersFilepath string
}

func (s Storage) validate() (err error) {
	if *s.ServersEnabled {
		_, err := filepath.Abs(s.ServersPath)
		if err != nil {
			return fmt.Errorf("servers path is not valid: %w", err)
		}
		_, err = filepath.Abs(s.LegacyServersFilepath)
		if err != nil {
			return fmt.Errorf("legacy servers filepath is not valid: %w", err)
		}
	}
	return nil
}

func (s *Storage) copy() (copied Storage) {
	return Storage{
		ServersEnabled:        gosettings.CopyPointer(s.ServersEnabled),
		ServersPath:           s.ServersPath,
		LegacyServersFilepath: s.LegacyServersFilepath,
	}
}

func (s *Storage) overrideWith(other Storage) {
	s.ServersEnabled = gosettings.OverrideWithPointer(s.ServersEnabled, other.ServersEnabled)
	s.ServersPath = gosettings.OverrideWithComparable(s.ServersPath, other.ServersPath)
	s.LegacyServersFilepath = gosettings.OverrideWithComparable(s.LegacyServersFilepath, other.LegacyServersFilepath)
}

const defaultLegacyServersFilepath = "/gluetun/servers.json"

func (s *Storage) SetDefaults() {
	s.ServersEnabled = gosettings.DefaultPointer(s.ServersEnabled, true)
	const defaultServersPath = "/gluetun/servers/"
	s.ServersPath = gosettings.DefaultComparable(s.ServersPath, defaultServersPath)
	s.LegacyServersFilepath = gosettings.DefaultComparable(s.LegacyServersFilepath, defaultLegacyServersFilepath)
}

func (s Storage) String() string {
	return s.toLinesNode().String()
}

func (s Storage) toLinesNode() (node *gotree.Node) {
	if !*s.ServersEnabled {
		return gotree.New("Storage settings: disabled")
	}
	node = gotree.New("Storage settings:")
	node.Appendf("Servers directory path: %s", s.ServersPath)
	if s.LegacyServersFilepath != defaultLegacyServersFilepath {
		node.Appendf("Legacy servers filepath: %s", s.LegacyServersFilepath)
	}
	return node
}

func (s *Storage) Read(r *reader.Reader) (err error) {
	// Retro-compatibility:
	// TODO v4: remove support for STORAGE_FILEPATH
	filePath := r.Get("STORAGE_FILEPATH", reader.AcceptEmpty(true), reader.IsRetro("STORAGE_SERVERS_DIRECTORY_PATH"))
	if filePath != nil {
		if *filePath == "" {
			s.ServersEnabled = ptrTo(false)
		} else {
			s.LegacyServersFilepath = *filePath
		}
	} else {
		s.ServersEnabled, err = r.BoolPtr("STORAGE_SERVERS_ENABLED")
		if err != nil {
			return err
		}
		s.ServersPath = r.String("STORAGE_SERVERS_DIRECTORY_PATH")
	}
	return nil
}
