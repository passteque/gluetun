package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Metrics_SetDefaults(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		initial  Metrics
		expected Metrics
	}{
		"empty settings": {
			expected: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9090",
				},
			},
		},
		"non empty settings": {
			initial: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
			expected: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.initial.setDefaults()

			assert.Equal(t, testCase.expected, testCase.initial)
		})
	}
}

func Test_Metrics_Copy(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		initial  Metrics
		expected Metrics
	}{
		"empty settings": {},
		"non empty settings": {
			initial: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
			expected: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			copied := testCase.initial.copy()

			assert.Equal(t, testCase.expected, copied)
		})
	}
}

func Test_Metrics_OverrideWith(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Metrics
		other    Metrics
		expected Metrics
	}{
		"override empty with empty": {},
		"override empty with filled": {
			other: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
			expected: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
		},
		"override filled with empty": {
			settings: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
			expected: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
		},
		"override filled with filled": {
			settings: Metrics{
				Type: "noop",
				Prometheus: Prometheus{
					ListeningAddress: ":9091",
				},
			},
			other: Metrics{
				Type: "prometheus",
				Prometheus: Prometheus{
					ListeningAddress: ":9092",
				},
			},
			expected: Metrics{
				Type: "prometheus",
				Prometheus: Prometheus{
					ListeningAddress: ":9092",
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.settings.overrideWith(testCase.other)

			assert.Equal(t, testCase.expected, testCase.settings)
		})
	}
}

func Test_Metrics_Validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings   Metrics
		errMessage string
	}{
		"invalid type": {
			settings: Metrics{
				Type: "unknown",
			},
			errMessage: "type: value is not one of the possible choices: " +
				"unknown must be one of prometheus or noop",
		},
		"invalid prometheus listening address": {
			settings: Metrics{
				Type: "prometheus",
				Prometheus: Prometheus{
					ListeningAddress: ":x",
				},
			},
			errMessage: "prometheus: listening address: " +
				"port value is not an integer: x",
		},
		"valid noop settings": {
			settings: Metrics{
				Type: "noop",
			},
		},
		"valid prometheus settings": {
			settings: Metrics{
				Type: "prometheus",
				Prometheus: Prometheus{
					ListeningAddress: ":9090",
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.validate()

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Metrics_String(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings Metrics
		s        string
	}{
		"noop metrics": {
			settings: Metrics{
				Type: "noop",
			},
			s: `Metrics settings:
└── Type: noop`,
		},
		"prometheus metrics": {
			settings: Metrics{
				Type: "prometheus",
				Prometheus: Prometheus{
					ListeningAddress: ":9090",
				},
			},
			s: `Metrics settings:
├── Type: prometheus
└── Prometheus:
    └── Listening address: :9090`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := testCase.settings.String()

			assert.Equal(t, testCase.s, s)
		})
	}
}
