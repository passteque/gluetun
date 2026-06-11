package cli

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/configuration/sources/files"
	"github.com/qdm12/gluetun/internal/configuration/sources/secrets"
	"github.com/qdm12/gluetun/internal/storage"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
)

type storageSetupLogger interface {
	storage.Logger
	files.Warner
}

func setupStorage(logger storageSetupLogger) (s *storage.Storage, err error) {
	settingsReader := reader.New(reader.Settings{
		Sources: []reader.Source{
			secrets.New(logger),
			files.New(logger),
			env.New(env.Settings{}),
		},
	})
	var settings settings.Storage
	err = settings.Read(settingsReader)
	if err != nil {
		return nil, fmt.Errorf("reading storage settings: %w", err)
	}
	settings.SetDefaults()
	storage, err := storage.New(logger, *settings.ServersEnabled, settings.ServersPath,
		settings.LegacyServersFilepath)
	if err != nil {
		return nil, fmt.Errorf("creating storage: %w", err)
	}
	return storage, nil
}
