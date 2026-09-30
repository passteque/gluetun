//go:build linux

package nftables

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// runResult is the (output, error) returned by a single nft command in
// RunUserPostRules tests.
type runResult struct {
	output string
	err    error
}

// expectedWarning is the expected line number and line text of a warning
// emitted by parseUserRules.
type expectedWarning struct {
	lineNum int
	line    string
}

func Test_parseUserRules(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content         string
		expectedRules   []userRule
		expectedWarning *expectedWarning
	}{
		"single_rule": {
			content: "nft add table x",
			expectedRules: []userRule{
				{lineNum: 1, line: "nft add table x", args: []string{"add", "table", "x"}},
			},
		},
		"multiple_rules": {
			content: "nft add table x\nnft flush ruleset",
			expectedRules: []userRule{
				{lineNum: 1, line: "nft add table x", args: []string{"add", "table", "x"}},
				{lineNum: 2, line: "nft flush ruleset", args: []string{"flush", "ruleset"}},
			},
		},
		"comment_skipped": {
			content: "# comment\nnft add table x",
			expectedRules: []userRule{
				{lineNum: 2, line: "nft add table x", args: []string{"add", "table", "x"}},
			},
		},
		"non_nft_warned": {
			content:       "echo hello\nnft add table x",
			expectedRules: []userRule{{lineNum: 2, line: "nft add table x", args: []string{"add", "table", "x"}}},
			expectedWarning: &expectedWarning{
				lineNum: 1,
				line:    "echo hello",
			},
		},
		"nftables_prefix_warned": {
			content:       "nftables foo",
			expectedRules: nil,
			expectedWarning: &expectedWarning{
				lineNum: 1,
				line:    "nftables foo",
			},
		},
		"tab_after_nft": {
			content: "nft\tadd table x",
			expectedRules: []userRule{
				{lineNum: 1, line: "nft\tadd table x", args: []string{"add", "table", "x"}},
			},
		},
		"nft_no_args": {
			content: "nft",
		},
		"empty": {
			content: "",
		},
		"whitespace_only": {
			content: "   \n  ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockLogger := NewMockLogger(ctrl)
			if testCase.expectedWarning != nil {
				mockLogger.EXPECT().Warnf(
					gomock.Eq("line %d: skipping unrecognized command (expected nft): %s"),
					gomock.Eq(testCase.expectedWarning.lineNum),
					gomock.Eq(testCase.expectedWarning.line),
				)
			}

			rules := parseUserRules([]byte(testCase.content), mockLogger)

			assert.Equal(t, testCase.expectedRules, rules)
		})
	}
}

func writeUserRulesFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "post-rules.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func Test_RunUserPostRules(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content       string
		missing       bool
		runResults    []runResult
		expectedError string
		expectSave    bool
		expectRestore bool
	}{
		"file_not_exist": {
			missing: true,
		},
		"no_nft_lines": {
			content: "# only a comment\n\n",
		},
		"success": {
			content:    "nft add table x\nnft flush ruleset",
			runResults: []runResult{{output: "ok"}, {output: "ok"}},
			expectSave: true,
		},
		"failure_restores": {
			content:       "nft add table x\nnft badcommand",
			runResults:    []runResult{{output: "ok"}, {output: "err output", err: errors.New("nft failed")}},
			expectedError: "running user rule on line 2",
			expectSave:    true,
			expectRestore: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			mockRunner := NewMockCmdRunner(ctrl)
			mockLogger := NewMockLogger(ctrl)

			dialed := false
			f := &Firewall{
				dialFunc: func() (conn, error) { dialed = true; return mockConn, nil },
				runner:   mockRunner,
				logger:   mockLogger,
			}

			var path string
			if !testCase.missing {
				path = writeUserRulesFile(t, testCase.content)
			} else {
				path = filepath.Join(t.TempDir(), "does-not-exist.txt")
			}

			if testCase.expectSave {
				// Save phase: no tables present.
				mockConn.EXPECT().ListTables().Return(nil, nil)
				mockConn.EXPECT().ListChains().Return(nil, nil)
			}

			for _, result := range testCase.runResults {
				mockRunner.EXPECT().Run(gomock.Any()).DoAndReturn(
					func(_ *exec.Cmd) (string, error) {
						return result.output, result.err
					},
				)
			}

			if testCase.expectRestore {
				// Restore phase: no tables present (saved or created), just a
				// listing and a flush.
				mockConn.EXPECT().ListTables().Return(nil, nil)
				mockConn.EXPECT().Flush().Return(nil)
			}

			err := f.RunUserPostRules(t.Context(), path)

			if testCase.expectedError != "" {
				assert.ErrorContains(t, err, testCase.expectedError)
			} else {
				assert.NoError(t, err)
			}
			if testCase.expectSave {
				assert.True(t, dialed)
			} else {
				assert.False(t, dialed)
			}
		})
	}
}
