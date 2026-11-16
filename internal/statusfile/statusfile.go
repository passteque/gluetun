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
// An existing file the process cannot open for writing sees its
// permissions set on a best-effort basis and the open retried once,
// see [openWritable].
// If the permissions or the ownership cannot be set, the content is
// still written, both are still attempted and the error returned
// wraps [ErrChmod], [ErrChown] or both.
// Writing in place keeps single file bind mounts working.
func Write(path string, content []byte, puid, pgid int) (err error) {
	// TODO v4: remove world permission (0660)
	const permission = fs.FileMode(0o664)
	file, err := openWritable(path, permission)
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

// openWritable opens the file for writing, truncating its content and
// creating it with the given permissions if it does not exist.
//
// An existing file can have permissions not granting this process write
// access, for example one chowned to PUID with the 0644 permissions used
// before v3.42.0, and the open is then denied with a permission error.
// The permissions of a file owned by another user can only be set with
// CAP_FOWNER, which can be dropped, so they are set on a best-effort
// basis after the failed open and the open is retried once.
// The error of the first open is returned when the file still cannot be
// opened, since it describes the situation the user starts from.
func openWritable(path string, permission fs.FileMode) (*os.File, error) {
	const flags = os.O_TRUNC | os.O_WRONLY | os.O_CREATE
	file, openErr := os.OpenFile(path, flags, permission)
	if !errors.Is(openErr, fs.ErrPermission) {
		return file, openErr
	}

	// Only worth trying for a regular file with permissions different from
	// the wanted ones, otherwise the retry is bound to fail too. The file
	// information is taken without following a symbolic link, so a link
	// pointing to a file of the system cannot have its permissions changed
	// by this program, which runs as root.
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() == permission {
		return nil, openErr
	}

	chmodErr := os.Chmod(path, permission)
	if chmodErr != nil {
		return nil, openErr
	}

	file, reopenErr := os.OpenFile(path, flags, permission)
	if reopenErr != nil {
		return nil, openErr
	}
	return file, nil
}
