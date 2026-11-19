package updater

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hostToServer_adaptWithIPs(t *testing.T) {
	t.Parallel()

	const (
		hostResolved = "de2-udp.ptoserver.com"
		hostStale    = "us2-udp.ptoserver.com"
		hostMissing  = "ca2-udp.ptoserver.com"
	)
	resolvedIP := netip.MustParseAddr("51.178.110.160")
	staleIP := netip.MustParseAddr("185.53.178.10")

	testCases := map[string]struct {
		hosts         []string
		hostToIPs     map[string][]netip.Addr
		expectedHosts []string
		expectedIPs   []netip.Addr
	}{
		"resolved_host_kept_with_resolved_ips": {
			hosts:     []string{hostResolved},
			hostToIPs: map[string][]netip.Addr{hostResolved: {resolvedIP}},
			expectedHosts: []string{
				hostResolved,
			},
			expectedIPs: []netip.Addr{resolvedIP},
		},
		"host_without_resolved_ip_is_discarded": {
			hosts:         []string{hostStale},
			hostToIPs:     map[string][]netip.Addr{hostStale: nil},
			expectedHosts: []string{},
		},
		"host_absent_from_resolution_is_discarded": {
			hosts:         []string{hostMissing},
			hostToIPs:     map[string][]netip.Addr{},
			expectedHosts: []string{},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hts := make(hostToServer)
			for _, host := range testCase.hosts {
				hts.add(host, []netip.Addr{staleIP}, false, true, []uint16{15021}, nil, false)
			}

			hts.adaptWithIPs(testCase.hostToIPs)

			hosts := hts.toHostsSlice()
			slices.Sort(hosts)
			assert.Equal(t, testCase.expectedHosts, hosts)
			if len(testCase.expectedIPs) == 0 {
				return
			}
			assert.Equal(t, testCase.expectedIPs, hts[testCase.expectedHosts[0]].IPs)
		})
	}
}
