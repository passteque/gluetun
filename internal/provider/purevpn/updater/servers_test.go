package updater

import (
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_Updater_withLocations(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		servers    []models.Server
		minServers int
		warnings   []string
		kept       []models.Server
		errWrapped error
		errMessage string
	}{
		"known_country_and_city_from_hostname": {
			servers: []models.Server{{
				Hostname: "usny2-udp.ptoserver.com",
			}},
			kept: []models.Server{{
				Hostname: "usny2-udp.ptoserver.com",
				Country:  "United States",
				City:     "New York",
				Region:   "New York",
			}},
		},
		"inventory_city_kept_when_hostname_has_no_city": {
			servers: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				City:     "Somewhere",
			}},
			kept: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				Country:  "United States",
				City:     "Somewhere",
			}},
		},
		"unknown_country_with_inventory_city_dropped": {
			servers: []models.Server{{
				Hostname: "zz2-udp.ptoserver.com",
				City:     "Somewhere",
			}},
			warnings: []string{
				`unknown country code "zz" in hostname "zz2-udp.ptoserver.com"`,
			},
			kept: []models.Server{},
		},
		"not_enough_servers_after_dropping": {
			servers: []models.Server{
				{Hostname: "usny2-udp.ptoserver.com"},
				{
					Hostname: "zz2-udp.ptoserver.com",
					City:     "Somewhere",
				},
			},
			minServers: 2,
			warnings: []string{
				`unknown country code "zz" in hostname "zz2-udp.ptoserver.com"`,
			},
			errWrapped: common.ErrNotEnoughServers,
			errMessage: "not enough servers found: 1 and expected at least 2",
		},
		"exactly_min_servers": {
			servers: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
			}},
			minServers: 1,
			kept: []models.Server{{
				Hostname: "us2-udp.ptoserver.com",
				Country:  "United States",
			}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			warner := common.NewMockWarner(ctrl)
			for _, warning := range testCase.warnings {
				warner.EXPECT().Warn(warning).Times(1)
			}

			updater := &Updater{logger: warner}

			kept, err := updater.withLocations(testCase.servers, testCase.minServers)

			assert.Equal(t, testCase.kept, kept)
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
