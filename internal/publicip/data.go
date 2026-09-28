package publicip

import "github.com/qdm12/gluetun/internal/models"

// GetData returns the public IP data obtained from the last
// fetch. It is notably used by the HTTP control server.
func (l *Loop) GetData() (data models.PublicIP) {
	l.ipDataMutex.RLock()
	defer l.ipDataMutex.RUnlock()
	return l.ipData
}

// ClearData is used when the VPN connection goes down
// and the public IP is not known anymore.
func (l *Loop) ClearData() (err error) {
	// Stop retrying to fetch the public IP information until the
	// next tunnel up trigger, since the VPN tunnel is going down.
	l.retryWanted.Store(false)

	l.ipDataMutex.Lock()
	defer l.ipDataMutex.Unlock()
	l.ipData = models.PublicIP{}

	l.settingsMutex.RLock()
	filepath := *l.settings.IPFilepath
	l.settingsMutex.RUnlock()
	return persistPublicIP(filepath, "", l.puid, l.pgid)
}
