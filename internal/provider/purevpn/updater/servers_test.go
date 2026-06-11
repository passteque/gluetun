package updater

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_needsGeolocationEnrichment(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		server models.Server
		need   bool
	}{
		"country and city present": {
			server: models.Server{
				Country:  "United States",
				Hostname: "usnj2-auto-udp.ptoserver.com",
				City:     "Newark",
			},
			need: false,
		},
		"missing country": {
			server: models.Server{Hostname: "us2-auto-udp.ptoserver.com", City: "Newark"},
			need:   true,
		},
		"missing city but hostname has no city code": {
			server: models.Server{Country: "United States", Hostname: "us2-auto-udp.ptoserver.com"},
			need:   false,
		},
		"missing city with city code in hostname": {
			server: models.Server{Country: "United States", Hostname: "usnj2-auto-udp.ptoserver.com"},
			need:   true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			need := needsGeolocationEnrichment(testCase.server)
			assert.Equal(t, testCase.need, need)
		})
	}
}

func Test_hostnameHasCityCode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		hostname string
		hasCode  bool
	}{
		"with city code": {
			hostname: "usnj2-auto-udp.ptoserver.com",
			hasCode:  true,
		},
		"without city code": {
			hostname: "us2-auto-udp.ptoserver.com",
			hasCode:  false,
		},
		"missing marker": {
			hostname: "invalid-hostname",
			hasCode:  false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hasCode := hostnameHasCityCode(testCase.hostname)
			assert.Equal(t, testCase.hasCode, hasCode)
		})
	}
}

func Test_canApplyGeolocationCountry(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inventoryCountry   string
		geolocationCountry string
		ok                 bool
	}{
		"empty inventory country": {
			inventoryCountry:   "",
			geolocationCountry: "Germany",
			ok:                 true,
		},
		"empty geolocation country": {
			inventoryCountry:   "Germany",
			geolocationCountry: "",
			ok:                 true,
		},
		"matching countries": {
			inventoryCountry:   "India",
			geolocationCountry: "India",
			ok:                 true,
		},
		"matching countries case insensitive": {
			inventoryCountry:   "United States",
			geolocationCountry: "united states",
			ok:                 true,
		},
		"mismatching countries": {
			inventoryCountry:   "Russia",
			geolocationCountry: "Germany",
			ok:                 false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ok := canApplyGeolocationCountry(testCase.inventoryCountry, testCase.geolocationCountry)
			assert.Equal(t, testCase.ok, ok)
		})
	}
}

func Test_mergeHostToServer(t *testing.T) {
	t.Parallel()

	base := make(hostToServer)
	base.add("us2-auto-udp.ptoserver.com", false, true, 15021, false)

	overlay := make(hostToServer)
	overlay.add("usnj2-auto-tcp.ptoserver.com", true, false, 80, false)
	overlay.add("us2-auto-udp.ptoserver.com", false, true, 1210, false)

	mergeHostToServer(base, overlay)

	assert.Contains(t, base, "usnj2-auto-tcp.ptoserver.com")
	assert.Contains(t, base["usnj2-auto-tcp.ptoserver.com"].TCPPorts, uint16(80))
	assert.ElementsMatch(t, []uint16{15021, 1210}, base["us2-auto-udp.ptoserver.com"].UDPPorts)
}

func Test_mergeHostToFallbackIPs(t *testing.T) {
	t.Parallel()

	base := map[string][]netip.Addr{
		"us2-auto-udp.ptoserver.com": {netip.MustParseAddr("1.1.1.1")},
	}
	overlay := map[string][]netip.Addr{
		"us2-auto-udp.ptoserver.com":   {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")},
		"usnj2-auto-tcp.ptoserver.com": {netip.MustParseAddr("3.3.3.3")},
	}

	merged := mergeHostToFallbackIPs(base, overlay)

	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2.2.2.2"),
	}, merged["us2-auto-udp.ptoserver.com"])
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("3.3.3.3"),
	}, merged["usnj2-auto-tcp.ptoserver.com"])
}
