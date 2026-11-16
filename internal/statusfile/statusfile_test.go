//go:build linux || darwin

package statusfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Write(t *testing.T) {
	t.Parallel()

	type owner struct{ uid, gid int }
	type file struct {
		content string
		mode    fs.FileMode
		owner   owner
	}

	self := owner{uid: os.Getuid(), gid: os.Getgid()}
	// other and third are users other than the one running the test.
	other := owner{uid: self.uid + 1, gid: self.gid + 1}
	third := owner{uid: self.uid + 2, gid: self.gid + 2}

	testCases := map[string]struct {
		// rootOnly is set for cases changing the ownership of a file to
		// another user, which needs root.
		rootOnly bool
		// nonRootOnly is set for cases relying on file permission checks,
		// which root bypasses.
		nonRootOnly bool
		// withoutChown, withoutFowner and withoutDACOverride are set for
		// cases running without CAP_CHOWN, CAP_FOWNER and CAP_DAC_OVERRIDE,
		// which are dropped when running as root.
		withoutChown       bool
		withoutFowner      bool
		withoutDACOverride bool
		missingParent      bool
		existing           *file // nil means no existing file
		// symlink is the file the tested path is a symbolic link to,
		// instead of being a regular file.
		symlink  *file
		content  string
		owner    owner
		errs     []error
		expected *file // nil means no file
	}{
		"create_file": {
			content:  "1.2.3.4",
			owner:    self,
			expected: &file{content: "1.2.3.4", mode: 0o664, owner: self},
		},
		"overwrite_file": {
			existing: &file{content: "1.2.3.4", mode: 0o664, owner: self},
			content:  "5.6",
			owner:    self,
			expected: &file{content: "5.6", mode: 0o664, owner: self},
		},
		"clear_file": {
			existing: &file{content: "1.2.3.4", mode: 0o664, owner: self},
			owner:    self,
			expected: &file{mode: 0o664, owner: self},
		},
		"file_with_mode_0600": {
			existing: &file{content: "1.2.3.4", mode: 0o600, owner: self},
			content:  "5.6.7.8",
			owner:    self,
			expected: &file{content: "5.6.7.8", mode: 0o664, owner: self},
		},
		"file_with_mode_0644": {
			existing: &file{content: "1.2.3.4", mode: 0o644, owner: self},
			content:  "5.6.7.8",
			owner:    self,
			expected: &file{content: "5.6.7.8", mode: 0o664, owner: self},
		},
		"missing_parent_directory": {
			missingParent: true,
			content:       "1.2.3.4",
			owner:         self,
			errs:          []error{fs.ErrNotExist},
		},
		// The open fails and the file, owned by this user, is chmoded
		// without any capability needed, which lets the write succeed.
		"read_only_file_of_self": {
			nonRootOnly: true,
			existing:    &file{content: "1.2.3.4", mode: 0o444, owner: self},
			content:     "5.6.7.8",
			owner:       self,
			expected:    &file{content: "5.6.7.8", mode: 0o664, owner: self},
		},
		"chown_to_other_user": {
			rootOnly: true,
			content:  "1.2.3.4",
			owner:    other,
			expected: &file{content: "1.2.3.4", mode: 0o664, owner: other},
		},
		// File left by v3.41.0, which wrote it with mode 0644.
		"file_of_other_user_with_mode_0644": {
			rootOnly: true,
			existing: &file{content: "1.2.3.4", mode: 0o644, owner: other},
			content:  "5.6.7.8",
			owner:    other,
			expected: &file{content: "5.6.7.8", mode: 0o664, owner: other},
		},
		// File left by v3.41.0 when CAP_DAC_OVERRIDE is dropped, which is
		// the case this program cannot open, hence cannot write to.
		// The permissions are set thanks to CAP_FOWNER and the write
		// succeeds, which heals the file for the next runs.
		"file_of_other_user_with_mode_0644_without_dac_override": {
			rootOnly:           true,
			withoutDACOverride: true,
			existing:           &file{content: "1.2.3.4", mode: 0o644, owner: other},
			content:            "5.6.7.8",
			owner:              other,
			expected:           &file{content: "5.6.7.8", mode: 0o664, owner: other},
		},
		// Same file but without CAP_FOWNER to repair it, which leaves the
		// permission error of the open, and none of the write errors since
		// nothing has been written.
		"file_of_other_user_without_dac_override_and_fowner": {
			rootOnly:           true,
			withoutChown:       true,
			withoutFowner:      true,
			withoutDACOverride: true,
			existing:           &file{content: "1.2.3.4", mode: 0o644, owner: other},
			content:            "5.6.7.8",
			owner:              other,
			errs:               []error{fs.ErrPermission},
			expected:           &file{content: "1.2.3.4", mode: 0o644, owner: other},
		},
		// The symbolic link is not followed to read the file information,
		// so the file it points to keeps its permissions and content.
		"symbolic_link_to_read_only_file": {
			nonRootOnly: true,
			symlink:     &file{content: "1.2.3.4", mode: 0o444, owner: self},
			content:     "5.6.7.8",
			owner:       self,
			errs:        []error{fs.ErrPermission},
			expected:    &file{content: "1.2.3.4", mode: 0o444, owner: self},
		},
		// The chmod and the chown are not needed, hence not done,
		// since they would fail without the capabilities.
		"file_of_other_user_without_capabilities": {
			rootOnly:      true,
			withoutChown:  true,
			withoutFowner: true,
			existing:      &file{content: "1.2.3.4", mode: 0o664, owner: other},
			content:       "5.6.7.8",
			owner:         other,
			expected:      &file{content: "5.6.7.8", mode: 0o664, owner: other},
		},
		// The chmod is done before the chown, since it would fail
		// without CAP_FOWNER once the file is owned by another user.
		"chmod_then_chown_without_fowner": {
			rootOnly:      true,
			withoutFowner: true,
			existing:      &file{content: "1.2.3.4", mode: 0o644, owner: self},
			content:       "5.6.7.8",
			owner:         other,
			expected:      &file{content: "5.6.7.8", mode: 0o664, owner: other},
		},
		"chmod_not_permitted": {
			rootOnly:      true,
			withoutFowner: true,
			existing:      &file{content: "1.2.3.4", mode: 0o644, owner: other},
			content:       "5.6.7.8",
			owner:         other,
			errs:          []error{ErrChmod, fs.ErrPermission},
			expected:      &file{content: "5.6.7.8", mode: 0o644, owner: other},
		},
		"chown_not_permitted": {
			withoutChown: true,
			existing:     &file{content: "1.2.3.4", mode: 0o644, owner: self},
			content:      "5.6.7.8",
			owner:        other,
			errs:         []error{ErrChown, fs.ErrPermission},
			expected:     &file{content: "5.6.7.8", mode: 0o664, owner: self},
		},
		"chmod_and_chown_not_permitted": {
			rootOnly:      true,
			withoutChown:  true,
			withoutFowner: true,
			existing:      &file{content: "1.2.3.4", mode: 0o644, owner: other},
			content:       "5.6.7.8",
			owner:         third,
			errs:          []error{ErrChmod, ErrChown, fs.ErrPermission},
			expected:      &file{content: "5.6.7.8", mode: 0o644, owner: other},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const root = 0
			isRoot := os.Geteuid() == root
			switch {
			case testCase.rootOnly && !isRoot:
				t.Skip("root is needed to change the ownership of a file to another user")
			case testCase.nonRootOnly && isRoot:
				t.Skip("root bypasses file permission checks")
			}

			path := filepath.Join(t.TempDir(), "file")
			if testCase.missingParent {
				path = filepath.Join(t.TempDir(), "missing", "file")
			}

			createFile := func(t *testing.T, path string, file file) {
				t.Helper()
				err := os.WriteFile(path, []byte(file.content), file.mode)
				require.NoError(t, err)
				// chmod explicitly since WriteFile is subject to the umask
				err = os.Chmod(path, file.mode)
				require.NoError(t, err)
				err = os.Chown(path, file.owner.uid, file.owner.gid)
				require.NoError(t, err)
			}

			switch {
			case testCase.symlink != nil:
				targetPath := path + "-target"
				createFile(t, targetPath, *testCase.symlink)
				err := os.Symlink(targetPath, path)
				require.NoError(t, err)
			case testCase.existing != nil:
				createFile(t, path, *testCase.existing)
			}

			if isRoot &&
				(testCase.withoutChown || testCase.withoutFowner || testCase.withoutDACOverride) {
				dropCapabilities(t,
					testCase.withoutChown, testCase.withoutFowner, testCase.withoutDACOverride)
			}

			err := Write(path, []byte(testCase.content), testCase.owner.uid, testCase.owner.gid)

			if len(testCase.errs) == 0 {
				assert.NoError(t, err)
			}
			for _, sentinelErr := range [...]error{ErrChmod, ErrChown, fs.ErrPermission, fs.ErrNotExist} {
				expected := slices.Contains(testCase.errs, sentinelErr)
				assert.Equal(t, expected, errors.Is(err, sentinelErr), "wrapping %q", sentinelErr)
			}

			if testCase.expected == nil {
				_, err = os.Stat(path)
				assert.ErrorIs(t, err, fs.ErrNotExist)
				return
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			info, err := os.Stat(path)
			require.NoError(t, err)
			stat, ok := info.Sys().(*syscall.Stat_t)
			require.True(t, ok)
			actual := file{
				content: string(data),
				mode:    info.Mode().Perm(),
				owner:   owner{uid: int(stat.Uid), gid: int(stat.Gid)},
			}
			assert.Equal(t, *testCase.expected, actual)
		})
	}
}

func Test_capabilityHint(t *testing.T) {
	t.Parallel()

	const capability = "CAP_FOWNER"
	testCases := map[string]struct {
		err      error
		expected string
	}{
		"permission_error": {
			err:      &fs.PathError{Op: "chmod", Path: "/file", Err: fs.ErrPermission},
			expected: ", CAP_FOWNER is required",
		},
		// The hint would be misleading, since the permissions cannot be
		// set whatever the capabilities of the program are.
		"read_only_file_system_error": {
			err:      &fs.PathError{Op: "chmod", Path: "/file", Err: syscall.EROFS},
			expected: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hint := capabilityHint(testCase.err, capability)

			assert.Equal(t, testCase.expected, hint)
		})
	}
}
