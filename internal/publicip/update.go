package publicip

import (
	"fmt"
	"os"
	"reflect"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/publicip/api"
)

func (l *Loop) update(partialUpdate settings.PublicIP) (err error) {
	l.settingsMutex.Lock()
	defer l.settingsMutex.Unlock()

	updatedSettings, err := l.settings.UpdateWith(partialUpdate)
	if err != nil {
		return err
	}

	if *l.settings.IPFilepath != *updatedSettings.IPFilepath {
		switch {
		case *l.settings.IPFilepath == "":
			err = l.persistPublicIP(*updatedSettings.IPFilepath, l.ipData.IP.String())
			if err != nil {
				return fmt.Errorf("persisting ip data: %w", err)
			}
		case *updatedSettings.IPFilepath == "":
			err = os.Remove(*l.settings.IPFilepath)
			if err != nil {
				return fmt.Errorf("removing ip data file path: %w", err)
			}
		default:
			err = os.Rename(*l.settings.IPFilepath, *updatedSettings.IPFilepath)
			if err != nil {
				return fmt.Errorf("renaming ip data file path: %w", err)
			}
		}
	}

	if !reflect.DeepEqual(l.settings.APIs, updatedSettings.APIs) {
		newFetchers, err := api.New(makeNameTokenPairs(updatedSettings.APIs), l.httpClient)
		if err != nil {
			return fmt.Errorf("creating fetchers: %w", err)
		}

		l.fetcher.UpdateFetchers(newFetchers)
	}

	l.settings = updatedSettings

	return nil
}
