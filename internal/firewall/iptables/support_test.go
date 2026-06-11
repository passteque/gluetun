package iptables

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func newAppendTestRuleMatcher(path string) *cmdMatcher {
	return newCmdMatcher(path,
		"^-A$", "^OUTPUT$", "^-o$", "^[a-z0-9]{15}$",
		"^-j$", "^DROP$")
}

func newDeleteTestRuleMatcher(path string) *cmdMatcher {
	return newCmdMatcher(path,
		"^-D$", "^OUTPUT$", "^-o$", "^[a-z0-9]{15}$",
		"^-j$", "^DROP$")
}

func newListInputRulesMatcher(path string) *cmdMatcher {
	return newCmdMatcher(path,
		"^-nL$", "^INPUT$")
}

func newSetPolicyMatcher(path, inputPolicy string) *cmdMatcher { //nolint:unparam
	return newCmdMatcher(path,
		"^--policy$", "^INPUT$", "^"+inputPolicy+"$")
}

func Test_checkIptablesSupport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	errDummy := errors.New("exit code 4")
	const inputPolicy = "ACCEPT"

	testCases := map[string]struct {
		buildRunner        func(ctrl *gomock.Controller) CmdRunner
		iptablesPathsToTry []string
		iptablesPath       string
		errMessage         string
	}{
		"critical error when checking": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path1")).
					Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher("path1")).
					Return("output", errDummy)
				return runner
			},
			iptablesPathsToTry: []string{"path1", "path2"},
			errMessage: "for path1: failed cleaning up test rule: " +
				"output (exit code 4)",
		},
		"found valid path": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path1")).
					Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher("path1")).
					Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher("path1")).
					Return("Chain INPUT (policy "+inputPolicy+")", nil)
				runner.EXPECT().Run(newSetPolicyMatcher("path1", inputPolicy)).
					Return("", nil)
				return runner
			},
			iptablesPathsToTry: []string{"path1", "path2"},
			iptablesPath:       "path1",
		},
		"all permission denied": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path1")).
					Return("Permission denied (you must be root) more context", errDummy)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path2")).
					Return("context: Permission denied (you must be root)", errDummy)
				return runner
			},
			iptablesPathsToTry: []string{"path1", "path2"},
			errMessage: "NET_ADMIN capability is missing: " +
				"path1: Permission denied (you must be root) more context (exit code 4); " +
				"path2: context: Permission denied (you must be root) (exit code 4)",
		},
		"no valid path": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path1")).
					Return("output 1", errDummy)
				runner.EXPECT().Run(newAppendTestRuleMatcher("path2")).
					Return("output 2", errDummy)
				return runner
			},
			iptablesPathsToTry: []string{"path1", "path2"},
			errMessage: "no iptables supported found: " +
				"errors encountered are: " +
				"path1: output 1 (exit code 4); " +
				"path2: output 2 (exit code 4)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			runner := testCase.buildRunner(ctrl)

			iptablesPath, err := checkIptablesSupport(ctx, runner, testCase.iptablesPathsToTry...)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.iptablesPath, iptablesPath)
		})
	}
}

func Test_testIptablesPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const path = "dummypath"
	errDummy := errors.New("exit code 4")
	const inputPolicy = "ACCEPT"

	testCases := map[string]struct {
		buildRunner        func(ctrl *gomock.Controller) CmdRunner
		ok                 bool
		unsupportedMessage string
		criticalErrMessage string
	}{
		"append test rule permission denied": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).
					Return("Permission denied (you must be root)", errDummy)
				return runner
			},
			unsupportedMessage: "Permission denied (you must be root) (exit code 4)",
		},
		"append test rule unsupported": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).
					Return("some output", errDummy)
				return runner
			},
			unsupportedMessage: "some output (exit code 4)",
		},
		"remove test rule error": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).
					Return("some output", errDummy)
				return runner
			},
			criticalErrMessage: "failed cleaning up test rule: some output (exit code 4)",
		},
		"list input rules permission denied": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("Permission denied (you must be root)", errDummy)
				return runner
			},
			unsupportedMessage: "Permission denied (you must be root) (exit code 4)",
		},
		"list input rules unsupported": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("some output", errDummy)
				return runner
			},
			unsupportedMessage: "some output (exit code 4)",
		},
		"list input rules no policy": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("some\noutput", nil)
				return runner
			},
			criticalErrMessage: "input policy not found: in INPUT rules: some\noutput",
		},
		"set policy permission denied": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("\nChain INPUT (policy "+inputPolicy+")\nAA\n", nil)
				runner.EXPECT().Run(newSetPolicyMatcher(path, inputPolicy)).
					Return("Permission denied (you must be root)", errDummy)
				return runner
			},
			unsupportedMessage: "Permission denied (you must be root) (exit code 4)",
		},
		"set policy unsupported": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("\nChain INPUT (policy "+inputPolicy+")\nBB\n", nil)
				runner.EXPECT().Run(newSetPolicyMatcher(path, inputPolicy)).
					Return("some output", errDummy)
				return runner
			},
			unsupportedMessage: "some output (exit code 4)",
		},
		"success": {
			buildRunner: func(ctrl *gomock.Controller) CmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newAppendTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newDeleteTestRuleMatcher(path)).Return("", nil)
				runner.EXPECT().Run(newListInputRulesMatcher(path)).
					Return("\nChain INPUT (policy "+inputPolicy+")\nCC\n", nil)
				runner.EXPECT().Run(newSetPolicyMatcher(path, inputPolicy)).
					Return("some output", nil)
				return runner
			},
			ok: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			runner := testCase.buildRunner(ctrl)

			ok, unsupportedMessage, criticalErr := testIptablesPath(ctx, path, runner)

			assert.Equal(t, testCase.ok, ok)
			assert.Equal(t, testCase.unsupportedMessage, unsupportedMessage)
			if testCase.criticalErrMessage != "" {
				assert.EqualError(t, criticalErr, testCase.criticalErrMessage)
			} else {
				assert.NoError(t, criticalErr)
			}
		})
	}
}

func Test_isPermissionDenied(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		errMessage string
		ok         bool
	}{
		"empty error": {},
		"other error": {
			errMessage: "some error",
		},
		"permission denied": {
			errMessage: "Permission denied (you must be root) have you tried blabla",
			ok:         true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ok := isPermissionDenied(testCase.errMessage)

			assert.Equal(t, testCase.ok, ok)
		})
	}
}

func Test_extractInputPolicy(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		line   string
		policy string
		ok     bool
	}{
		"empty line": {},
		"random line": {
			line: "random line",
		},
		"only first part": {
			line: "Chain INPUT (policy ",
		},
		"empty policy": {
			line: "Chain INPUT (policy )",
		},
		"ACCEPT policy": {
			line:   "Chain INPUT (policy ACCEPT)",
			policy: "ACCEPT",
			ok:     true,
		},

		"ACCEPT policy with surrounding garbage": {
			line:   "garbage Chain INPUT (policy   ACCEPT\t) )g()arbage",
			policy: "ACCEPT",
			ok:     true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			policy, ok := extractInputPolicy(testCase.line)

			assert.Equal(t, testCase.policy, policy)
			assert.Equal(t, testCase.ok, ok)
		})
	}
}

func Test_randomInterfaceName(t *testing.T) {
	t.Parallel()

	const expectedRegex = `^[a-z0-9]{15}$`
	interfaceName := randomInterfaceName()
	assert.Regexp(t, expectedRegex, interfaceName)
}
