// Package statusfile writes status files, such as the public IP
// address file or the forwarded port file, readable by other programs.
package statusfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

var (
	// ErrChmod is wrapped by the error [Write] returns when the content
	// is written but the file permissions cannot be set.
	ErrChmod = errors.New("file permissions not set")
	// ErrChown is wrapped by the error [Write] returns when the content
	// is written but the file ownership cannot be set.
	ErrChown = errors.New("file ownership not set")
)

// Write writes the content to the file at the given path in place,
// creating it if needed, then sets its permissions to 0664 and its
// ownership to puid and pgid, each only if it differs. A puid or pgid
// of -1 leaves the corresponding ownership unchanged.
// If the permissions or the ownership cannot be set, the content is
// still written, both are still attempted and the error returned
// wraps [ErrChmod], [ErrChown] or both.
// Writing in place keeps single file bind mounts working.
func Write(path string, content []byte, puid, pgid int) (err error) {
	// TODO v4: remove world permission (0660)
	const permission = fs.FileMode(0o664)
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, permission)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}

	_, err = file.Write(content)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("writing file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("getting file information: %w", err)
	}

	// OpenFile is subject to the umask and leaves the permissions of an
	// existing file unchanged, hence the chmod. On a file owned by another
	// user, such as one previously chowned to puid, the chmod needs
	// CAP_FOWNER and the chown needs CAP_CHOWN, even to set the same owner.
	// Both capabilities may be dropped, so each is only done when needed.
	// The chmod comes first, since a file just created is still owned by
	// this process, which then needs no capability to chmod it.
	var chmodErr, chownErr error
	if info.Mode().Perm() != permission {
		err = file.Chmod(permission)
		if err != nil {
			chmodErr = fmt.Errorf("%w: %w", ErrChmod, err)
		}
	}

	if !isOwnedBy(info, puid, pgid) {
		err = file.Chown(puid, pgid)
		if err != nil {
			chownErr = fmt.Errorf("%w: %w", ErrChown, err)
		}
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing file: %w", err)
	}

	return errors.Join(chmodErr, chownErr)
}
