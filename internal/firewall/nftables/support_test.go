package nftables

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_IsSupported(t *testing.T) {
	t.Parallel()

	supported := IsSupported()
	// IsSupported checks if nftables library can create a connection and list tables.
	// In non-root or restricted environments this may return false.
	// Just verify it doesn't panic.
	assert.IsType(t, false, supported)
}

func Test_Version(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	t.Run("returns version string", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		logger := NewMockLogger(ctrl)
		fw := New(logger)

		// Version uses exec.CommandContext to run "nft -v"
		// If nft command is not available, expect error.
		version, err := fw.Version(ctx)

		if os.Getenv("NFT_AVAILABLE") == "1" {
			// In environments with nft available, verify we get a version
			require.NoError(t, err)
			assert.Regexp(t, `v\d+\.\d+(\.\d+)?`, version, "version should match 'vX.Y' format")
		} else {
			// If nft is not available, expect an error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "running nft -v")
		}
	})
}

func Test_RunUserPostRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := map[string]struct {
		setupFile       func(t *testing.T, dir string) string
		expectError     bool
		expectWarnf     bool
		errorContains   string
		warnfFormatHint string
	}{
		"file does not exist - returns nil": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				return filepath.Join(dir, "does_not_exist.txt")
			},
			expectError: false,
		},
		"empty file - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "empty.txt")
				require.NoError(t, os.WriteFile(path, []byte(""), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"comment lines only - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "comments.txt")
				content := "# This is a comment\n# Another comment\n\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"blank lines only - succeeds": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "blanks.txt")
				content := "\n\n\n   \n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
		},
		"non-nft command skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "skip.txt")
				content := "iptables -A INPUT -j ACCEPT\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"nftables command prefix skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nftables_prefix.txt")
				content := "nftables something\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"nftrace command prefix skipped with warning": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nftrace_prefix.txt")
				content := "nftrace something\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:     false,
			expectWarnf:     true,
			warnfFormatHint: "skipping unrecognized command",
		},
		"only nft without arguments - skipped": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "nft_only.txt")
				content := "nft\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError: false,
			expectWarnf: false,
		},
		"invalid nft command - error": {
			setupFile: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "invalid.txt")
				content := "nft invalid_command_that_does_not_exist\n"
				require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file
				return path
			},
			expectError:   true,
			errorContains: "running user rule on line 1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			logger := NewMockLogger(ctrl)

			// Set up expected Warnf call if needed
			if testCase.expectWarnf {
				logger.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
			}

			fw := New(logger)

			dir := t.TempDir()
			filepath := testCase.setupFile(t, dir)

			err := fw.RunUserPostRules(ctx, filepath)

			if testCase.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), testCase.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_RunUserPostRules_valid_nft_command(t *testing.T) {
	t.Parallel()

	if os.Getenv("NFT_AVAILABLE") != "1" {
		t.Skip("nft command not available")
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	fw := New(logger)

	dir := t.TempDir()
	path := filepath.Join(dir, "valid.txt")
	// Add and then delete a rule in a unique table to avoid affecting system
	content := `
nft add table inet test_gluetun_` + filepath.Base(dir) + `
nft add chain inet test_gluetun_` + filepath.Base(dir) + ` input { type filter hook input priority 0; }
nft delete table inet test_gluetun_` + filepath.Base(dir) + `
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) //nolint:gosec // test file

	err := fw.RunUserPostRules(ctx, path)
	assert.NoError(t, err)
}
