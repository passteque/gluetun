package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_setupFilterWithBaseChains(t *testing.T) {
	t.Parallel()

	conn, err := nftables.New()
	require.NoError(t, err)

	table, inputChain, forwardChain, outputChain := setupFilterWithBaseChains(conn)

	require.NotNil(t, table)
	assert.Equal(t, nftables.TableFamilyINet, table.Family)
	assert.Equal(t, "filter", table.Name)

	// Verify all chains reference the same table
	require.NotNil(t, inputChain)
	require.NotNil(t, forwardChain)
	require.NotNil(t, outputChain)
	assert.Equal(t, table, inputChain.Table)
	assert.Equal(t, table, forwardChain.Table)
	assert.Equal(t, table, outputChain.Table)

	// Verify input chain properties
	assert.Equal(t, "input", inputChain.Name)
	assert.Equal(t, nftables.ChainTypeFilter, inputChain.Type)
	assert.Equal(t, nftables.ChainHookInput, inputChain.Hooknum)
	assert.Equal(t, nftables.ChainPriorityFilter, inputChain.Priority)

	// Verify forward chain properties
	assert.Equal(t, "forward", forwardChain.Name)
	assert.Equal(t, nftables.ChainTypeFilter, forwardChain.Type)
	assert.Equal(t, nftables.ChainHookForward, forwardChain.Hooknum)
	assert.Equal(t, nftables.ChainPriorityFilter, forwardChain.Priority)

	// Verify output chain properties
	assert.Equal(t, "output", outputChain.Name)
	assert.Equal(t, nftables.ChainTypeFilter, outputChain.Type)
	assert.Equal(t, nftables.ChainHookOutput, outputChain.Hooknum)
	assert.Equal(t, nftables.ChainPriorityFilter, outputChain.Priority)
}
