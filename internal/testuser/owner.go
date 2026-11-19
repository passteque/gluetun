package testuser

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// UnrelatedOwner returns a user ID and a group ID which the process running
// the test does not have, so the kernel applies the file permission checks
// to the files owned by this owner.
//
// The group is the first one from 1000 which is neither the group nor one of
// the supplementary groups of the process running the test. This matters
// since a group shared with the process, for example group 1 when the test
// runs as root, satisfies the file permission checks through the group
// permissions and hides the case tested, such as opening a file owned by
// another user without CAP_DAC_OVERRIDE.
func UnrelatedOwner(t *testing.T) (uid, gid int) {
	t.Helper()

	const baseGID = 1000
	groups, err := os.Getgroups()
	require.NoError(t, err)

	gid = baseGID
	for gid == os.Getgid() || slices.Contains(groups, gid) {
		gid++
	}

	// The user ID does not have to match an account of the system, only to
	// differ from the one of the process running the test.
	const uidOffset = 3
	return os.Getuid() + uidOffset, gid
}
