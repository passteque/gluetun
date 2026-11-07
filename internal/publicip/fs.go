package publicip

import "github.com/qdm12/gluetun/internal/statusfile"

func persistPublicIP(path string, content string, puid, pgid int) error {
	return statusfile.Write(path, []byte(content), puid, pgid)
}
