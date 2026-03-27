package wireguard

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AddRule(t *testing.T) {
	t.Parallel()

	const rulePriority uint32 = 987
	const firewallMark uint32 = 456
	const family = netlink.FamilyV4

	errDummy := errors.New("dummy")

	testCases := map[string]struct {
		expectedRule netlink.Rule
		ruleAddErr   error
		err          error
		ruleDelErr   error
		cleanupErr   error
	}{
		"success": {
			expectedRule: netlink.Rule{
				Priority: ptrTo(rulePriority),
				Mark:     ptrTo(firewallMark),
				Table:    firewallMark,
				Family:   family,
				Flags:    netlink.FlagInvert,
				Action:   netlink.ActionToTable,
			},
		},
		"rule add error": {
			expectedRule: netlink.Rule{
				Priority: ptrTo(rulePriority),
				Mark:     ptrTo(firewallMark),
				Table:    firewallMark,
				Family:   family,
				Flags:    netlink.FlagInvert,
				Action:   netlink.ActionToTable,
			},
			ruleAddErr: errDummy,
			err:        errors.New("adding ip rule 987: from all to all table 456: dummy"),
		},
		"rule delete error": {
			expectedRule: netlink.Rule{
				Priority: ptrTo(rulePriority),
				Mark:     ptrTo(firewallMark),
				Table:    firewallMark,
				Family:   family,
				Flags:    netlink.FlagInvert,
				Action:   netlink.ActionToTable,
			},
			ruleDelErr: errDummy,
			cleanupErr: errors.New("deleting rule ip rule 987: from all to all table 456: dummy"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			netLinker := NewMockNetLinker(ctrl)

			netLinker.EXPECT().RuleAdd(testCase.expectedRule).
				Return(testCase.ruleAddErr)
			cleanup, err := AddRule(rulePriority, firewallMark, family,
				netLinker, nil)
			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
				return
			}

			require.NoError(t, err)

			netLinker.EXPECT().RuleDel(testCase.expectedRule).
				Return(testCase.ruleDelErr)
			err = cleanup()
			if testCase.cleanupErr != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.cleanupErr.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
