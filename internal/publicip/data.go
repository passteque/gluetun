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
	// Stop the attempt pending until the next tunnel up, the VPN connection
	// going down being what pulls it: fetching with no connection answers
	// nothing but timeouts, and the tunnel up which follows triggers a fetch of
	// its own which starts the delays over. The send cannot block, the channel
	// is buffered and the run loop is its only reader; a token already queued
	// says the same thing as this one, so it is dropped rather than queued.
	select {
	case l.retryStopTrigger <- struct{}{}:
	default:
	}

	l.ipDataMutex.Lock()
	defer l.ipDataMutex.Unlock()
	l.ipData = models.PublicIP{}

	l.settingsMutex.RLock()
	filepath := *l.settings.IPFilepath
	l.settingsMutex.RUnlock()
	return l.persistPublicIP(filepath, "")
}
