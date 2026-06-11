package storage

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/qdm12/gluetun/internal/models"
)

type Storage struct {
	mergedServers models.AllServers
	mergedMutex   sync.RWMutex
	// this is stored in memory to avoid re-parsing
	// the embedded JSON file on every call to the
	// SyncServers method.
	hardcodedServers models.AllServers
	logger           Logger
	disk             bool
	directoryPath    string
	legacyFilepath   string
}

const manifestFilename = "manifest.json"

type Logger interface {
	Info(s string)
	Infof(format string, args ...any)
	Warn(s string)
}

// New creates a new storage and reads the servers from the
// embedded servers files and the files on disk.
// Passing an empty directoryPath disables the reading and writing of
// servers.
func New(logger Logger, disk bool, directoryPath, legacyFilepath string) (storage *Storage, err error) {
	// A unit test prevents [parseHardcodedServers] from ever failing,
	// and ensures all providers are part of the servers returned.
	hardcodedServers := parseHardcodedServers()

	storage = &Storage{
		hardcodedServers: hardcodedServers,
		mergedServers:    hardcodedServers,
		logger:           logger,
		disk:             disk,
		directoryPath:    directoryPath,
		legacyFilepath:   legacyFilepath,
	}

	if disk {
		if err := storage.syncServers(); err != nil {
			return nil, err
		}
	}

	return storage, nil
}

// hasLegacy returns true if the legacy file `legacyFilepath` exists AND is
// different from the manifest file defined by `directoryPath`/[manifestFilename].
// This is used to determine if the legacy file should be read and removed after flushing servers data.
func (s *Storage) hasLegacy() bool {
	if !s.disk {
		return false
	}
	if filepath.Clean(filepath.Join(s.directoryPath, manifestFilename)) ==
		filepath.Clean(s.legacyFilepath) {
		return false
	}
	stat, err := os.Stat(s.legacyFilepath)
	return err == nil && !stat.IsDir()
}
