package settings

import (
	"testing"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/require"
)

func Test_defaultDNSProviders(t *testing.T) {
	t.Parallel()

	names := defaultDNSProviders()

	found := false
	providers := provider.NewProviders()
	for _, name := range names {
		provider, err := providers.Get(name)
		require.NoError(t, err)
		if len(provider.Plain.IPv4) > 0 {
			found = true
			break
		}
	}
	require.True(t, found, "no default DNS provider has a plaintext IPv4 address")
}
