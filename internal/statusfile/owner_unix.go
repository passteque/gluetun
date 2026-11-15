//go:build linux || darwin

package statusfile

import (
	"io/fs"
	"syscall"
)

// isOwnedBy returns true if the file is owned by the user id and
// group id given, where -1 matches any id, as for [os.Chown].
func isOwnedBy(info fs.FileInfo, uid, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	const anyID = -1
	uidMatches := uid == anyID || uid == int(stat.Uid)
	gidMatches := gid == anyID || gid == int(stat.Gid)
	return uidMatches && gidMatches
}
