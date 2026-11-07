package service

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/statusfile"
)

func (s *Service) writePortForwardedFile(ports []uint16) (err error) {
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprint(int(port))
	}
	fileData := []byte(strings.Join(portStrings, "\n"))

	filepath := s.settings.Filepath
	if len(ports) == 0 {
		s.logger.Info("clearing port file " + filepath)
	} else {
		s.logger.Info("writing port file " + filepath)
	}

	// TODO v4: is it necessary/desirable to chown to PUID?
	// Once owned by PUID, gluetun needs CAP_DAC_OVERRIDE to update the
	// file and CAP_FOWNER to chmod it if its permissions changed, and
	// PGID already has read/write access after the chmod, unless the
	// chmod was skipped due to a permission error. To keep the
	// file UID unchanged, use os.Chown(filepath, -1, s.pgid), that is
	// statusfile.Write(filepath, fileData, -1, s.pgid).
	return statusfile.Write(filepath, fileData, s.puid, s.pgid)
}
