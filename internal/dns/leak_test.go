package dns

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_leakCheck(t *testing.T) {
	t.Parallel()

	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	client := http.DefaultClient
	report, err := leakCheck(ctx, client)
	require.NoError(t, err)
	require.NotEmpty(t, report)
}
