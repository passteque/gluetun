//go:build !linux && !darwin

package statusfile

import "io/fs"

// IsOwnedBy always returns false, since the file ownership
// cannot be read on this platform.
func IsOwnedBy(_ fs.FileInfo, _, _ int) bool {
	return false
}
