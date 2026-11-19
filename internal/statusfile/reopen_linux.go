//go:build linux

package statusfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// reopenWritable retries opening for writing the file at the given path,
// after a first open failed with the permission error openErr, see
// [OpenWritable].
//
// The file is first opened with O_PATH and O_NOFOLLOW, which needs no
// permission on the file and does not follow a symbolic link, and every
// change and the reopen are then made through that file descriptor. They
// therefore all apply to the regular file which was checked, even if its
// path is replaced in the meantime, so a path replaced by a symbolic link
// to a file of the system cannot make this program, running as root,
// change the permissions of that file.
//
// If the reopen fails, the original permissions and ownership are
// restored. The file can be left writable by everyone, with the write
// permission for others added thanks to CAP_FOWNER, only if the process
// stops in between or if restoring the permissions fails. Another process
// could also open the file for writing in that window and keep using that
// file descriptor afterwards.
func reopenWritable(path string, permission fs.FileMode, openErr error) (*os.File, error) {
	pathFD, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, openErr
	}
	defer func() {
		_ = unix.Close(pathFD)
	}()

	// Only worth trying for a regular file not yet writable by everyone,
	// otherwise the retry is bound to fail too. A symbolic link, opened
	// itself because of O_NOFOLLOW, is not a regular file.
	var stat unix.Stat_t
	err = unix.Fstat(pathFD, &stat)
	const writableByAll = 0o222
	if err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&writableByAll == writableByAll {
		return nil, openErr
	}

	openErr = fmt.Errorf(
		"%w, CAP_DAC_OVERRIDE, CAP_FOWNER or CAP_CHOWN is required", openErr)

	// fchmod does not work on a file descriptor opened with O_PATH, and
	// fchmodat with AT_SYMLINK_NOFOLLOW is not supported by older kernels,
	// so the permissions are changed through the magic link of the file
	// descriptor, which leads to the file it refers to whatever its path.
	fdPath := "/proc/self/fd/" + strconv.Itoa(pathFD)
	const permissionBits = 0o7777
	originalMode := stat.Mode & permissionBits
	err = unix.Chmod(fdPath, originalMode|writableByAll)
	tookOwnership := false
	if errors.Is(err, unix.EPERM) {
		// Without CAP_FOWNER, this process can still take the ownership of
		// the file with CAP_CHOWN, and an owner can change the permissions
		// of its file to grant itself write access.
		err = unix.Fchownat(pathFD, "", os.Geteuid(), -1, unix.AT_EMPTY_PATH)
		if err != nil {
			return nil, openErr
		}
		tookOwnership = true
		const writableByOwner = 0o200
		if originalMode&writableByOwner == 0 {
			err = unix.Chmod(fdPath, originalMode|writableByOwner)
		}
	}

	// The file descriptor still refers to the file which was checked, so
	// restoring through it is safe. The permissions are restored first,
	// while this process may still be the owner of the file.
	restore := func() {
		_ = unix.Chmod(fdPath, originalMode)
		if tookOwnership {
			_ = unix.Fchownat(pathFD, "", int(stat.Uid), int(stat.Gid), unix.AT_EMPTY_PATH)
		}
	}

	if err != nil {
		restore()
		return nil, openErr
	}

	// The file is only truncated once it is opened, and not created again
	// if it was removed since the first open.
	writeFD, err := unix.Open(fdPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		restore()
		return nil, openErr
	}
	file := os.NewFile(uintptr(writeFD), path)

	// The permissions were changed above, either thanks to CAP_FOWNER or
	// as the owner of the file, so this change is allowed too.
	err = file.Chmod(permission)
	if err != nil {
		_ = file.Close()
		restore()
		return nil, fmt.Errorf("setting file permissions: %w", err)
	}

	err = file.Truncate(0)
	if err != nil {
		_ = file.Close()
		restore()
		return nil, fmt.Errorf("truncating file: %w", err)
	}

	return file, nil
}
