//go:build linux || darwin

package statusfile

import (
	"io/fs"
	"syscall"
)

// IsOwnedBy returns true if the file is owned by the user id and
// group id given, where -1 matches any id, as for [os.Chown].
// The ownership of a file owned by another user can only be changed with
// CAP_CHOWN, even to set the same owner, and the capability can be
// dropped, so callers check with this function to only chown when needed.
func IsOwnedBy(info fs.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	const anyID = -1
	uidMatches := uid == anyID || uid == int(stat.Uid)
	gidMatches := gid == anyID || gid == int(stat.Gid)
	return uidMatches && gidMatches
}
