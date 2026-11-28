package settings

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_HTTPProxy_setDefaults(t *testing.T) {
	t.Parallel()

	const customTimeout = 5 * time.Second

	testCases := map[string]struct {
		settings HTTPProxy
		expected HTTPProxy
	}{
		"empty_settings": {
			settings: HTTPProxy{},
			expected: HTTPProxy{
				User:              new(""),
				Password:          new(""),
				ListeningAddress:  ":8888",
				Enabled:           new(false),
				Stealth:           new(false),
				Log:               new(false),
				ReadHeaderTimeout: time.Second,
			},
		},
		"filled_settings": {
			settings: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
			expected: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.settings.setDefaults()

			assert.Equal(t, testCase.expected, testCase.settings)
		})
	}
}

func Test_HTTPProxy_copy(t *testing.T) {
	t.Parallel()

	const customTimeout = 2 * time.Second

	testCases := map[string]struct {
		settings HTTPProxy
		expected HTTPProxy
	}{
		"empty_settings": {},
		"filled_settings": {
			settings: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
			expected: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			copied := testCase.settings.copy()

			assert.Equal(t, testCase.expected, copied)
		})
	}
}

func Test_HTTPProxy_overrideWith(t *testing.T) {
	t.Parallel()

	const customTimeout = 5 * time.Second

	testCases := map[string]struct {
		settings HTTPProxy
		other    HTTPProxy
		expected HTTPProxy
	}{
		"override_empty_with_empty": {},
		"override_empty_with_filled": {
			other: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
			expected: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
		},
		"override_filled_with_empty": {
			settings: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(true),
				Stealth:           new(false),
				Log:               new(false),
				ReadHeaderTimeout: time.Second,
			},
			expected: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(true),
				Stealth:           new(false),
				Log:               new(false),
				ReadHeaderTimeout: time.Second,
			},
		},
		"override_filled_with_filled": {
			settings: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(false),
				Stealth:           new(false),
				Log:               new(false),
				ReadHeaderTimeout: time.Second,
			},
			other: HTTPProxy{
				User:              new("bob"),
				Password:          new("other"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
			},
			expected: HTTPProxy{
				User:              new("bob"),
				Password:          new("other"),
				ListeningAddress:  ":9999",
				Enabled:           new(true),
				Stealth:           new(true),
				Log:               new(true),
				ReadHeaderTimeout: customTimeout,
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

func Test_HTTPProxy_String(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings HTTPProxy
		expected string
	}{
		"disabled": {
			settings: HTTPProxy{
				Enabled: new(false),
			},
			expected: `HTTP proxy settings:
└── Enabled: no`,
		},
		"enabled": {
			settings: HTTPProxy{
				User:              new("alice"),
				Password:          new("secret"),
				ListeningAddress:  ":8888",
				Enabled:           new(true),
				Stealth:           new(false),
				Log:               new(true),
				ReadHeaderTimeout: time.Second,
			},
			expected: `HTTP proxy settings:
├── Enabled: yes
├── Listening address: :8888
├── User: alice
├── Password: [set]
├── Stealth mode: no
├── Log: yes
└── Read header timeout: 1s`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := testCase.settings.String()

			assert.Equal(t, testCase.expected, result)
		})
	}
}
