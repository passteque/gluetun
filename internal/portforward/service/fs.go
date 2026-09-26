package service

import (
	"fmt"
	"os"
	"strings"
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

	// TODO v4: remove world permission (0660)
	const perms = os.FileMode(0o664)
	err = os.WriteFile(filepath, fileData, perms)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}
	// chmod explicitly since WriteFile is subject to the umask
	err = os.Chmod(filepath, perms)
	if err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	// TODO v4: is it necessary/desirable to chown to PUID?
	// Once owned by PUID, gluetun needs CAP_DAC_OVERRIDE to update the
	// file and CAP_FOWNER to chmod it, and PGID already has read/write
	// access after the chmod. To keep the file UID unchanged, use
	// os.Chown(filepath, -1, s.pgid).
	err = os.Chown(filepath, s.puid, s.pgid)
	if err != nil {
		return fmt.Errorf("chowning file: %w", err)
	}

	return nil
}
