//go:build !linux

package statusfile

import (
	"fmt"
	"io/fs"
	"os"
)

// reopenWritable retries opening for writing the file at the given path,
// after a first open failed with the permission error openErr, see
// [OpenWritable].
//
// The file information is taken without following a symbolic link, and the
// permissions are then changed through the path, so a path replaced in
// between by a symbolic link has the permissions of the file it points to
// changed. The opened file is checked to be the one first examined, before
// it is truncated and its permissions set.
// The file can be left writable by everyone if the reopen or the final
// chmod fails, if the path is replaced during the call, or if the process
// stops in between. Another process could also open the file for writing
// in that window and keep using that file descriptor afterwards.
func reopenWritable(path string, permission fs.FileMode, openErr error) (*os.File, error) {
	// Only worth trying for a regular file not yet writable by everyone,
	// otherwise the retry is bound to fail too.
	info, statErr := os.Lstat(path)
	const writableByAll = fs.FileMode(0o222)
	if statErr != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&writableByAll == writableByAll {
		return nil, openErr
	}

	openErr = fmt.Errorf("%w, CAP_DAC_OVERRIDE or CAP_FOWNER is required", openErr)
	chmodErr := os.Chmod(path, info.Mode().Perm()|writableByAll)
	if chmodErr != nil {
		return nil, openErr
	}

	// The file is only truncated once it is known to be the one checked,
	// and not created again if it was removed since the Lstat.
	file, reopenErr := os.OpenFile(path, os.O_WRONLY, 0)
	if reopenErr != nil {
		return nil, openErr
	}

	// Guards against the path being replaced between the Lstat and the open.
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		// The original file is left as is, since it can only be reached by
		// its path, which now leads to another file.
		return nil, openErr
	}

	// The chmod above succeeded, so this one is allowed too.
	chmodErr = file.Chmod(permission)
	if chmodErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("setting file permissions: %w", chmodErr)
	}

	truncateErr := file.Truncate(0)
	if truncateErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("truncating file: %w", truncateErr)
	}

	return file, nil
}
