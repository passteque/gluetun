package metrics

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings settings.Metrics
		expected string
	}{
		"noop_type": {
			settings: settings.Metrics{
				Type: "noop",
			},
			expected: "noop metrics service",
		},
		"prometheus_type": {
			settings: settings.Metrics{
				Type: "prometheus",
				Prometheus: settings.Prometheus{
					ListeningAddress: "127.0.0.1:0",
				},
			},
			expected: "prometheus http server",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service, err := New(testCase.settings, log.New(),
				NewMockVPNLooper(nil), NewMockLinkLister(nil))
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, service.String())
		})
	}
}

func Test_New_UnknownTypePanics(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "unknown metrics type: unknown", func() {
		_, _ = New(settings.Metrics{Type: "unknown"}, log.New(),
			NewMockVPNLooper(nil), NewMockLinkLister(nil))
	})
}
