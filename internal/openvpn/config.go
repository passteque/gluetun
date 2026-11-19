package openvpn

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/statusfile"
)

func (c *Configurator) WriteConfig(lines []string) error {
	const permission = 0o644
	// The container file system is kept across restarts, so the file is
	// often already there, owned by puid and pgid with the 0644
	// permissions above. This process running as root is then allowed to
	// open it only with CAP_DAC_OVERRIDE, CAP_FOWNER or CAP_CHOWN, which
	// can all be dropped, so the open repairs the file when needed, see
	// [statusfile.OpenWritable].
	file, err := statusfile.OpenWritable(c.configPath, permission)
	if err != nil {
		return err
	}
	_, err = file.WriteString(strings.Join(lines, "\n"))
	if err != nil {
		_ = file.Close()
		return err
	}

	// The configuration file is written at each OpenVPN start. Changing the
	// ownership of a file needs CAP_CHOWN even to set the same owner, and
	// the capability can be dropped, hence the check to only chown when it
	// differs. The open above may also have taken the ownership of the file
	// to repair it, which this chown gives back.
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
