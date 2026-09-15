//go:build linux

package nftables

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func testRule(table *nftables.Table, chain *nftables.Chain, handle uint64) *nftables.Rule {
	return &nftables.Rule{
		Table: table, Chain: chain, Handle: handle,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	}
}

// sampleState is the set of tables, chains, and rules used by save/restore
// tests: the backend-owned table with its chains and rules, and an unrelated
// user table which must be preserved by the restore.
type sampleState struct {
	gluetunTable    *nftables.Table
	userTable       *nftables.Table
	inputChain      *nftables.Chain
	forwardChain    *nftables.Chain
	outputChain     *nftables.Chain
	preroutingChain *nftables.Chain
	userChain       *nftables.Chain
	inputRules      []*nftables.Rule
	userRules       []*nftables.Rule
}

// buildSampleState creates the gluetun table (input/forward/output/prerouting
// chains) and a user table (userChain), with a couple of rules, for
// save/restore tests.
func buildSampleState() sampleState {
	gluetunTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: gluetunTableName}
	userTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: "user"}
	inputChain := &nftables.Chain{
		Name: inputChainName, Table: gluetunTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	}
	forwardChain := &nftables.Chain{
		Name: forwardChainName, Table: gluetunTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	}
	outputChain := &nftables.Chain{
		Name: outputChainName, Table: gluetunTable, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
	}
	preroutingChain := &nftables.Chain{
		Name: preroutingChainName, Table: gluetunTable, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,
	}
	userChain := &nftables.Chain{Name: "userChain", Table: userTable}

	inputRules := []*nftables.Rule{
		testRule(gluetunTable, inputChain, 10),
		testRule(gluetunTable, inputChain, 11),
	}
	userRules := []*nftables.Rule{
		testRule(userTable, userChain, 20),
	}
	return sampleState{
		gluetunTable:    gluetunTable,
		userTable:       userTable,
		inputChain:      inputChain,
		forwardChain:    forwardChain,
		outputChain:     outputChain,
		preroutingChain: preroutingChain,
		userChain:       userChain,
		inputRules:      inputRules,
		userRules:       userRules,
	}
}

func Test_saveTables(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	gluetunTable := state.gluetunTable
	userTable := state.userTable
	inputChain := state.inputChain
	forwardChain := state.forwardChain
	outputChain := state.outputChain
	preroutingChain := state.preroutingChain
	userChain := state.userChain
	inputRules := state.inputRules
	userRules := state.userRules

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	mockConn.EXPECT().ListTables().Return([]*nftables.Table{gluetunTable, userTable}, nil)
	mockConn.EXPECT().ListChains().Return(
		[]*nftables.Chain{inputChain, forwardChain, outputChain, preroutingChain, userChain}, nil,
	)
	mockConn.EXPECT().GetRules(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
			switch chain.Name {
			case inputChainName:
				return inputRules, nil
			case "userChain":
				return userRules, nil
			default:
				return nil, nil
			}
		},
	).Times(5)

	savedTables, err := saveTables(mockConn)

	assert.NoError(t, err)
	require.Len(t, savedTables, 2)

	assert.Equal(t, gluetunTable, savedTables[0].table)
	require.Len(t, savedTables[0].chains, 4)
	assert.Equal(t, inputRules, savedTables[0].chains[0].rules)
	assert.Empty(t, savedTables[0].chains[1].rules)
	assert.Empty(t, savedTables[0].chains[2].rules)
	assert.Empty(t, savedTables[0].chains[3].rules)

	assert.Equal(t, userTable, savedTables[1].table)
	require.Len(t, savedTables[1].chains, 1)
	assert.Equal(t, userRules, savedTables[1].chains[0].rules)
}

func Test_restoreTables(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	gluetunTable := state.gluetunTable
	userTable := state.userTable
	inputChain := state.inputChain
	userChain := state.userChain
	inputRules := state.inputRules
	userRules := state.userRules

	// A table created after the save, which the restore must delete.
	sessionTable := &nftables.Table{Family: nftables.TableFamilyINet, Name: "session"}

	savedTables := []savedTable{
		{
			table: gluetunTable,
			chains: []savedChain{
				{chain: inputChain, rules: inputRules},
			},
		},
		{
			table: userTable,
			chains: []savedChain{
				{chain: userChain, rules: userRules},
			},
		},
	}

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)

	var deletedTables []*nftables.Table
	var restoredChains []*nftables.Chain
	var addedRules []*nftables.Rule

	mockConn.EXPECT().ListTables().Return(
		[]*nftables.Table{gluetunTable, userTable, sessionTable}, nil,
	)
	mockConn.EXPECT().DelTable(sessionTable).Do(func(table *nftables.Table) {
		deletedTables = append(deletedTables, table)
	})
	mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
		return table
	}).Times(2)
	mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
		restoredChains = append(restoredChains, chain)
		return chain
	}).Times(2)
	mockConn.EXPECT().FlushChain(gomock.Any()).Times(2)
	mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
		addedRules = append(addedRules, rule)
		return rule
	}).Times(3)
	mockConn.EXPECT().Flush().Return(nil)

	err := restoreTables(mockConn, savedTables)

	assert.NoError(t, err)

	// The table created after the save is deleted.
	require.Len(t, deletedTables, 1)
	assert.Equal(t, sessionTable, deletedTables[0])

	// Two chains restored (input and userChain).
	require.Len(t, restoredChains, 2)
	assert.Equal(t, inputChainName, restoredChains[0].Name)
	assert.Equal(t, gluetunTable, restoredChains[0].Table)
	assert.Equal(t, "userChain", restoredChains[1].Name)
	assert.Equal(t, userTable, restoredChains[1].Table)

	// Three rules re-added (2 input + 1 user), all with handle 0 and
	// pointing at the restored chain.
	require.Len(t, addedRules, 3)
	for i, rule := range addedRules {
		assert.Zero(t, rule.Handle)
		if i < 2 {
			assert.Equal(t, restoredChains[0], rule.Chain)
			assert.Equal(t, inputRules[i].Exprs, rule.Exprs)
		} else {
			assert.Equal(t, restoredChains[1], rule.Chain)
			assert.Equal(t, userRules[i-2].Exprs, rule.Exprs)
		}
	}

	// The saved state must not be mutated, so restore can be called again.
	assert.Equal(t, uint64(10), inputRules[0].Handle)
	assert.Equal(t, inputChain, inputRules[0].Chain)
}

func Test_SaveAndRestore(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	gluetunTable := state.gluetunTable
	userTable := state.userTable
	userChain := state.userChain
	userRules := state.userRules

	savedRule := testRule(userTable, userChain, 100)
	sessionRule := testRule(gluetunTable, state.inputChain, 101)

	testCases := map[string]struct {
		staleOwnedTable     bool
		restoreFlushError   error
		restoreDialError    error
		expectWarningFormat string
	}{
		"success": {},
		"stale_owned_table_removed_on_save": {
			staleOwnedTable: true,
		},
		"restore_flush_error_logs_warning": {
			restoreFlushError:   errors.New("restore flush failed"),
			expectWarningFormat: "restoring nftables state",
		},
		"restore_dial_error_logs_warning_and_resets_tracker": {
			restoreDialError:    errors.New("restore dial failed"),
			expectWarningFormat: "creating nftables connection for restore",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockConn := NewMockConn(ctrl)
			mockLogger := NewMockLogger(ctrl)

			dialCount := 0
			f := &Firewall{
				dialFunc: func() (conn, error) {
					dialCount++
					if dialCount == 2 && testCase.restoreDialError != nil {
						return nil, testCase.restoreDialError
					}
					return mockConn, nil
				},
				logger: mockLogger,
			}

			// The tracker holds a rule at save time, to which the session
			// adds another rule before the restore.
			f.rules = []*nftables.Rule{savedRule}

			tablesAtSave := []*nftables.Table{userTable}
			if testCase.staleOwnedTable {
				tablesAtSave = append(tablesAtSave, gluetunTable)
			}

			// Save phase: stale owned table check.
			mockConn.EXPECT().ListTables().Return(tablesAtSave, nil)
			if testCase.staleOwnedTable {
				mockConn.EXPECT().DelTable(gluetunTable)
				mockConn.EXPECT().Flush().Return(nil)
			}

			// Save phase: state snapshot (the gluetun table is not present, so
			// only the user table is saved).
			mockConn.EXPECT().ListTables().Return([]*nftables.Table{userTable}, nil)
			mockConn.EXPECT().ListChains().Return([]*nftables.Chain{userChain}, nil)
			mockConn.EXPECT().GetRules(userTable, userChain).Return(userRules, nil)

			restore, err := f.SaveAndRestore(t.Context())
			require.NoError(t, err)
			require.NotNil(t, restore)

			// The session adds a rule after the save.
			f.rules = append(f.rules, sessionRule)

			if testCase.restoreDialError == nil {
				// Restore phase: the gluetun table was created by the session,
				// so it is deleted, and the saved user state is restored.
				mockConn.EXPECT().ListTables().Return(
					[]*nftables.Table{userTable, gluetunTable}, nil,
				)
				mockConn.EXPECT().DelTable(gluetunTable)
				mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
					return table
				})
				mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
					return chain
				})
				mockConn.EXPECT().FlushChain(gomock.Any())
				mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
					return rule
				}).Times(len(userRules))
				mockConn.EXPECT().Flush().Return(testCase.restoreFlushError)
			}

			if testCase.expectWarningFormat != "" {
				mockLogger.EXPECT().Warnf(gomock.Any(), gomock.Any()).
					Do(func(format string, _ ...any) {
						assert.Contains(t, format, testCase.expectWarningFormat)
					})
			}

			restore(t.Context())

			// The tracker is reset to the saved state.
			assert.Equal(t, []*nftables.Rule{savedRule}, f.rules)
		})
	}
}

// Test_SaveAndRestore_restore_idempotent verifies that the returned restore
// function can be called multiple times without mutating the saved state.
func Test_SaveAndRestore_restore_idempotent(t *testing.T) {
	t.Parallel()

	state := buildSampleState()
	gluetunTable := state.gluetunTable
	userTable := state.userTable
	userChain := state.userChain
	userRules := state.userRules

	ctrl := gomock.NewController(t)
	mockConn := NewMockConn(ctrl)
	f := &Firewall{dialFunc: func() (conn, error) { return mockConn, nil }}

	// Save phase: stale owned table check, then state snapshot.
	mockConn.EXPECT().ListTables().Return([]*nftables.Table{userTable}, nil)
	mockConn.EXPECT().ListTables().Return([]*nftables.Table{userTable}, nil)
	mockConn.EXPECT().ListChains().Return([]*nftables.Chain{userChain}, nil)
	mockConn.EXPECT().GetRules(userTable, userChain).Return(userRules, nil)

	// Two restore phases.
	for range 2 {
		mockConn.EXPECT().ListTables().Return(
			[]*nftables.Table{userTable, gluetunTable}, nil,
		)
		mockConn.EXPECT().DelTable(gluetunTable)
		mockConn.EXPECT().AddTable(gomock.Any()).DoAndReturn(func(table *nftables.Table) *nftables.Table {
			return table
		})
		mockConn.EXPECT().AddChain(gomock.Any()).DoAndReturn(func(chain *nftables.Chain) *nftables.Chain {
			return chain
		})
		mockConn.EXPECT().FlushChain(gomock.Any())
		mockConn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
			return rule
		}).Times(len(userRules))
		mockConn.EXPECT().Flush().Return(nil)
	}

	restore, err := f.SaveAndRestore(t.Context())
	require.NoError(t, err)

	restore(t.Context())
	restore(t.Context())

	// Saved state is intact after two restores.
	assert.Equal(t, uint64(20), userRules[0].Handle)
	assert.Equal(t, userChain, userRules[0].Chain)
}
