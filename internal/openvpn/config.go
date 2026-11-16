package openvpn

import (
	"fmt"
	"os"
	"strings"

	"github.com/qdm12/gluetun/internal/statusfile"
)

func (c *Configurator) WriteConfig(lines []string) error {
	const permission = 0o644
	file, err := os.OpenFile(c.configPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, permission)
	if err != nil {
		return err
	}
	_, err = file.WriteString(strings.Join(lines, "\n"))
	if err != nil {
		_ = file.Close()
		return err
	}

	// The configuration file is written at each OpenVPN start and the
	// container file system is kept across restarts, so the file is often
	// already owned by puid and pgid. Changing the ownership of a file
	// needs CAP_CHOWN even to set the same owner, and the capability can
	// be dropped, hence the check to only chown when it differs.
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("getting file information: %w", err)
	} else if !statusfile.IsOwnedBy(info, c.puid, c.pgid) {
		err = file.Chown(c.puid, c.pgid)
		if err != nil {
			_ = file.Close()
			return err
		}
	}

	return file.Close()
}
