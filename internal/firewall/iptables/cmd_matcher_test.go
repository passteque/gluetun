package iptables

import (
	"fmt"
	"os/exec"
	"regexp"

	"go.uber.org/mock/gomock"
)

var _ gomock.Matcher = (*cmdMatcher)(nil)

type cmdMatcher struct {
	path       string
	argsRegex  []string
	argsRegexp []*regexp.Regexp
}

func (cm *cmdMatcher) Matches(x interface{}) bool {
	cmd, ok := x.(*exec.Cmd)
	if !ok {
		return false
	}

	if cmd.Path != cm.path {
		return false
	}

	if len(cmd.Args) == 0 {
		return false
	}

	arguments := cmd.Args[1:]
	if len(arguments) != len(cm.argsRegex) {
		return false
	}

	for i, arg := range arguments {
		if !cm.argsRegexp[i].MatchString(arg) {
			return false
		}
	}

	return true
}

func (cm *cmdMatcher) String() string {
	return fmt.Sprintf("path %s, argument regular expressions %v", cm.path, cm.argsRegex)
}

func newCmdMatcher(path string, argsRegex ...string) *cmdMatcher {
	argsRegexp := make([]*regexp.Regexp, len(argsRegex))
	for i, argRegex := range argsRegex {
		argsRegexp[i] = regexp.MustCompile(argRegex)
	}
	return &cmdMatcher{
		path:       path,
		argsRegex:  argsRegex,
		argsRegexp: argsRegexp,
	}
}
