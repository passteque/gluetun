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
	l.ipDataMutex.Lock()
	defer l.ipDataMutex.Unlock()
	l.ipData = models.PublicIP{}

	l.settingsMutex.RLock()
	filepath := *l.settings.IPFilepath
	l.settingsMutex.RUnlock()
	err = l.persistPublicIP(filepath, "")

	// Stop the attempt pending until the next tunnel up, the VPN connection going
	// down being what pulls this: fetching with no connection answers nothing but
	// timeouts, and the tunnel up which follows triggers a fetch of its own which
	// starts the delays over. The send waits for the run loop to be back in its
	// select, a fetch it already has in hand being the longest it can hold on, and
	// gives up once the run loop is gone, [Loop.Stop] having canceled the run
	// context before calling this.
	select {
	case l.retryStopTrigger <- struct{}{}:
	case <-l.runCtx.Done():
	}

	return err
}
