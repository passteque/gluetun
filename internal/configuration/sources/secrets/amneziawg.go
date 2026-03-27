package secrets

import (
	"os"
	"path/filepath"

	"github.com/qdm12/gluetun/internal/configuration/sources/files"
)

func (s *Source) lazyLoadAmneziawgConf() files.AmneziawgConfig {
	if s.cached.amneziawgLoaded {
		return s.cached.amneziawgConf
	}

	path := os.Getenv("AMNEZIAWG_CONF_SECRETFILE")
	if path == "" {
		path = filepath.Join(s.rootDirectory, "amneziawg", "awg0.conf")
	}

	s.cached.amneziawgLoaded = true
	var err error
	s.cached.amneziawgConf, err = files.ParseAmneziawgConf(path)
	if err != nil {
		s.warner.Warnf("skipping Amneziawg config: %s", err)
	}
	return s.cached.amneziawgConf
}
