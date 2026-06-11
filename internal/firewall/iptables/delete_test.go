package iptables

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func Test_isDeleteMatchInstruction(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		instruction   string
		isDeleteMatch bool
	}{
		"not_delete": {
			instruction: "-t nat -A PREROUTING -i tun0 -j ACCEPT",
		},
		"malformed_missing_chain_name": {
			instruction: "-t nat -D",
		},
		"delete_chain_name_last_field": {
			instruction:   "-t nat --delete PREROUTING",
			isDeleteMatch: true,
		},
		"delete_match": {
			instruction:   "-t nat --delete PREROUTING -i tun0 -j ACCEPT",
			isDeleteMatch: true,
		},
		"delete_line_number_last_field": {
			instruction: "-t nat -D PREROUTING 2",
		},
		"delete_line_number": {
			instruction: "-t nat -D PREROUTING 2 -i tun0 -j ACCEPT",
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			isDeleteMatch := isDeleteMatchInstruction(testCase.instruction)

			assert.Equal(t, testCase.isDeleteMatch, isDeleteMatch)
		})
	}
}

func newCmdMatcherListRules(iptablesBinary, table, chain string) *cmdMatcher { //nolint:unparam
	return newCmdMatcher(iptablesBinary, "^-t$", "^"+table+"$", "^-L$", "^"+chain+"$",
		"^--line-numbers$", "^-n$", "^-v$")
}

func Test_deleteIPTablesRule(t *testing.T) {
	t.Parallel()

	const iptablesBinary = "/sbin/iptables"

	testCases := map[string]struct {
		instruction string
		makeRunner  func(ctrl *gomock.Controller) *MockCmdRunner
		makeLogger  func(ctrl *gomock.Controller) *MockLogger
		errMessage  string
	}{
		"invalid_instruction": {
			instruction: "invalid",
			errMessage: "parsing iptables command: parsing \"invalid\": " +
				"iptables command is malformed: flag \"invalid\" requires a value, but got none",
		},
		"list_error": {
			instruction: "-t nat --delete PREROUTING -i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678",
			makeRunner: func(ctrl *gomock.Controller) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().
					Run(newCmdMatcherListRules(iptablesBinary, "nat", "PREROUTING")).
					Return("", errors.New("test error"))
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug("/sbin/iptables -t nat -L PREROUTING --line-numbers -n -v")
				return logger
			},
			errMessage: `finding iptables chain rule line number: command failed: ` +
				`"/sbin/iptables -t nat -L PREROUTING --line-numbers -n -v": test error`,
		},
		"rule_not_found": {
			instruction: "-t nat --delete PREROUTING -i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678",
			makeRunner: func(ctrl *gomock.Controller) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcherListRules(iptablesBinary, "nat", "PREROUTING")).
					Return(`Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
		num   pkts bytes target     prot opt in     out     source               destination
		1        0     0 REDIRECT   6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 redir ports 9999`, //nolint:lll
						nil)
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug("/sbin/iptables -t nat -L PREROUTING --line-numbers -n -v")
				logger.EXPECT().Debug("rule matching \"-t nat --delete PREROUTING " +
					"-i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678\" not found")
				return logger
			},
		},
		"rule_found_delete_error": {
			instruction: "-t nat --delete PREROUTING -i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678",
			makeRunner: func(ctrl *gomock.Controller) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcherListRules(iptablesBinary, "nat", "PREROUTING")).
					Return("Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)\n"+
						"num   pkts bytes target     prot opt in     out     source               destination         \n"+
						"1        0     0 REDIRECT   6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 redir ports 9999\n"+ //nolint:lll
						"2        0     0 REDIRECT   6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:43716 redir ports 5678\n", //nolint:lll
						nil)
				runner.EXPECT().Run(newCmdMatcher(iptablesBinary, "^-t$", "^nat$",
					"^-D$", "^PREROUTING$", "^2$")).Return("details", errors.New("test error"))
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug("/sbin/iptables -t nat -L PREROUTING --line-numbers -n -v")
				logger.EXPECT().Debug("found iptables chain rule matching \"-t nat --delete PREROUTING " +
					"-i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678\" at line number 2")
				logger.EXPECT().Debug("/sbin/iptables -t nat -D PREROUTING 2")
				return logger
			},
			errMessage: "command failed: \"/sbin/iptables -t nat -D PREROUTING 2\": test error: details",
		},
		"rule_found_delete_success": {
			instruction: "-t nat --delete PREROUTING -i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678",
			makeRunner: func(ctrl *gomock.Controller) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcherListRules(iptablesBinary, "nat", "PREROUTING")).
					Return("Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)\n"+
						"num   pkts bytes target     prot opt in     out     source               destination         \n"+
						"1        0     0 REDIRECT   6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 redir ports 9999\n"+ //nolint:lll
						"2        0     0 REDIRECT   6    --  tun0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:43716 redir ports 5678\n", //nolint:lll
						nil)
				runner.EXPECT().Run(newCmdMatcher(iptablesBinary, "^-t$", "^nat$",
					"^-D$", "^PREROUTING$", "^2$")).Return("", nil)
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug("/sbin/iptables -t nat -L PREROUTING --line-numbers -n -v")
				logger.EXPECT().Debug("found iptables chain rule matching \"-t nat --delete PREROUTING " +
					"-i tun0 -p tcp --dport 43716 -j REDIRECT --to-ports 5678\" at line number 2")
				logger.EXPECT().Debug("/sbin/iptables -t nat -D PREROUTING 2")
				return logger
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			ctx := context.Background()
			instruction := testCase.instruction
			var runner *MockCmdRunner
			if testCase.makeRunner != nil {
				runner = testCase.makeRunner(ctrl)
			}
			var logger *MockLogger
			if testCase.makeLogger != nil {
				logger = testCase.makeLogger(ctrl)
			}

			err := deleteIPTablesRule(ctx, iptablesBinary, instruction, runner, logger)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
