//go:build !linux && !darwin

package statusfile

import "io/fs"

// isOwnedBy always returns false, since the file ownership
// cannot be read on this platform.
func isOwnedBy(_ fs.FileInfo, _, _ int) bool {
	return false
}
