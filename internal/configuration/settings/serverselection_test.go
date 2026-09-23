package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type noopFilterChoicesGetter struct{}

func (noopFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{}
}

func Test_ServerSelection_setDefaults_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		initial  ServerSelection
		expected string
	}{
		"empty_mode_set_to_random": {
			expected: "random",
		},
		"random_mode_kept": {
			initial:  ServerSelection{Mode: "random"},
			expected: "random",
		},
		"ordered_mode_kept": {
			initial:  ServerSelection{Mode: "ordered"},
			expected: "ordered",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.initial.setDefaults(providers.Mullvad, false)

			assert.Equal(t, testCase.expected, testCase.initial.Mode)
		})
	}
}

func Test_ServerSelection_validate_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mode       string
		errMessage string
	}{
		"random": {
			mode: "random",
		},
		"ordered": {
			mode: "ordered",
		},
		"empty": {
			errMessage: "the selection mode specified is not valid",
		},
		"invalid": {
			mode:       "invalid",
			errMessage: "the selection mode specified is not valid",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			warner := NewMockWarner(ctrl)

			ss := ServerSelection{}.WithDefaults(providers.Mullvad)
			ss.Mode = testCase.mode

			err := ss.validate(providers.Mullvad, noopFilterChoicesGetter{}, warner)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
