package publicip

import (
	"errors"

	"github.com/qdm12/gluetun/internal/statusfile"
)

// writeIPFile writes the content to the public IP address file.
// The permissions or the ownership of the file not being set
// is only logged, since the content is written at this point.
func (l *Loop) writeIPFile(path, content string) (err error) {
	err = statusfile.Write(path, []byte(content), l.puid, l.pgid)
	if errors.Is(err, statusfile.ErrChmod) || errors.Is(err, statusfile.ErrChown) {
		l.logger.Warn(err.Error())
		return nil
	}
	return err
}
