package iptables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_acceptOutputMarkedInstruction_requiresBootstrapSocketMark(t *testing.T) {
	t.Parallel()

	const bootstrapFirewallMark uint32 = 51820
	instruction := acceptOutputMarkedInstruction("tcp", "eth0",
		netip.MustParseAddr("198.51.100.10"), 443, bootstrapFirewallMark, false)

	assert.Equal(t, "--append OUTPUT -d 198.51.100.10 -o eth0 -p tcp -m tcp --dport 443 "+
		"-m mark --mark 51820 -j ACCEPT", instruction)
	parsedInstruction, err := parseIptablesInstruction(instruction)
	require.NoError(t, err)
	assert.Equal(t, uint(bootstrapFirewallMark), parsedInstruction.mark.value)
	assert.False(t, parsedInstruction.mark.invert)
}
