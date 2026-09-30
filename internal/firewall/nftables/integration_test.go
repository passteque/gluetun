//go:build linux

package nftables

import (
	"os"
	"os/exec"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIntegrationLogger is a no-op logger for integration tests.
type testIntegrationLogger struct{}

func (testIntegrationLogger) Warnf(string, ...any) {}

// testIntegrationCmdRunner is a no-op command runner for integration tests.
type testIntegrationCmdRunner struct{}

func (testIntegrationCmdRunner) Run(*exec.Cmd) (string, error) { return "", nil }

// TestIntegration_SaveAndRestore_no_leak verifies, against a real kernel,
// that disabling the firewall removes the backend-owned table (no DROP
// policy or rule leak) while pre-existing user state is preserved.
// It is skipped unless GLUETUN_NFTABLES_INTEGRATION=1 is set.
func TestIntegration_SaveAndRestore_no_leak(t *testing.T) {
	if os.Getenv("GLUETUN_NFTABLES_INTEGRATION") != "1" {
		t.Skip("set GLUETUN_NFTABLES_INTEGRATION=1 to run")
	}
	t.Parallel()

	ctx := t.Context()
	f := New(testIntegrationCmdRunner{}, testIntegrationLogger{})

	const userTableName = "gluetun_int_test_user"

	// Pre-existing user state: a table with a chain and a rule, which must
	// survive the firewall disable.
	userConn, err := nftables.New()
	require.NoError(t, err)
	userTable := userConn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: userTableName})
	userChain := userConn.AddChain(&nftables.Chain{Name: "userchain", Table: userTable})
	userConn.AddRule(&nftables.Rule{
		Table: userTable, Chain: userChain,
		Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
	})
	require.NoError(t, userConn.Flush())
	t.Cleanup(func() {
		userConn.DelTable(userTable)
		_ = userConn.Flush()
	})

	restore, err := f.SaveAndRestore(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { restore(ctx) })

	// Simulate an enable: an accept policy (never drops, so the host network
	// is unaffected) plus a tracked rule.
	require.NoError(t, f.SetBaseChainsPolicy(ctx, "accept"))
	require.NoError(t, f.AcceptInputThroughInterface(ctx, "*"))

	tables, err := f.listGluetunTables()
	require.NoError(t, err)
	assert.Contains(t, tables, gluetunTableName)
	assert.Contains(t, tables, userTableName)

	// Disable: the owned table must be gone, the user state preserved.
	restore(ctx)

	tables, err = f.listGluetunTables()
	require.NoError(t, err)
	assert.NotContains(t, tables, gluetunTableName)
	assert.Contains(t, tables, userTableName)

	userRules, err := userConn.GetRules(userTable, userChain)
	require.NoError(t, err)
	assert.Len(t, userRules, 1)
}

// listGluetunTables lists the names of the current inet tables.
func (f *Firewall) listGluetunTables() ([]string, error) {
	conn, err := f.dialFunc()
	if err != nil {
		return nil, err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet {
			names = append(names, table.Name)
		}
	}
	return names, nil
}
