package updater

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/provider/surfshark/servers"
)

func getHostInformation(host string, hostnameToLocation map[string]servers.ServerLocation) (
	data servers.ServerLocation, err error,
) {
	locationData, ok := hostnameToLocation[host]
	if !ok {
		return locationData, fmt.Errorf("hostname %s not found in hostname to location mapping", host)
	}

	return locationData, nil
}

func hostToLocation(locationData []servers.ServerLocation) (
	hostToLocation map[string]servers.ServerLocation,
) {
	hostToLocation = make(map[string]servers.ServerLocation, len(locationData))
	for _, data := range locationData {
		hostToLocation[data.Hostname] = data
	}
	return hostToLocation
}
