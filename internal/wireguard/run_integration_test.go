//go:build linux

package wireguard

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// teardownRecorder wraps a NetLinker to record the teardown operations
// and whether the Wireguard link still existed when each IP rule was removed.
type teardownRecorder struct {
	NetLinker
	linkName string

	mutex      sync.Mutex
	operations []string
	// linkExistedOnRuleDel is true if the link still existed
	// when at least one IP rule was removed.
	linkExistedOnRuleDel bool
}

func (r *teardownRecorder) RuleDel(rule netlink.Rule) error {
	_, linkErr := r.LinkByName(r.linkName)
	r.mutex.Lock()
	r.operations = append(r.operations, "rule delete")
	if linkErr == nil {
		r.linkExistedOnRuleDel = true
	}
	r.mutex.Unlock()
	return r.NetLinker.RuleDel(rule)
}

func (r *teardownRecorder) LinkDel(linkIndex uint32) error {
	r.mutex.Lock()
	r.operations = append(r.operations, "link delete")
	r.mutex.Unlock()
	return r.NetLinker.LinkDel(linkIndex)
}

func Test_Wireguard_Run_teardown_Integration(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		implementation string
		needsKernel    bool
		firewallMark   uint32
		rulePriority   uint32
		address        netip.Prefix
	}{
		"userspace": {
			implementation: "userspace",
			firewallMark:   61001,
			rulePriority:   10001,
			address:        netip.MustParsePrefix("10.211.0.2/32"),
		},
		"kernelspace": {
			implementation: "kernelspace",
			needsKernel:    true,
			firewallMark:   61002,
			rulePriority:   10002,
			address:        netip.MustParsePrefix("10.212.0.2/32"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			netlinker := netlink.New(&noopDebugLogger{})
			if testCase.needsKernel {
				supported, err := netlinker.IsWireguardSupported()
				require.NoError(t, err)
				if !supported {
					t.Skip("kernel does not support Wireguard")
				}
			}

			linkName := makeLinkName()
			recorder := &teardownRecorder{NetLinker: netlinker, linkName: linkName}

			privateKey, err := wgtypes.GeneratePrivateKey()
			require.NoError(t, err)
			peerKey, err := wgtypes.GeneratePrivateKey()
			require.NoError(t, err)

			settings := Settings{
				InterfaceName: linkName,
				PrivateKey:    privateKey.String(),
				PublicKey:     peerKey.PublicKey().String(),
				Endpoint:      netip.MustParseAddrPort("127.0.0.1:51820"),
				Addresses:     []netip.Prefix{testCase.address},
				// Documentation range so the test does not affect other traffic.
				AllowedIPs:     []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
				FirewallMark:   testCase.firewallMark,
				RulePriority:   testCase.rulePriority,
				IPv6:           new(false),
				Implementation: testCase.implementation,
				GSO:            new(false),
			}
			wireguard, err := New(settings, recorder, &noopDebugLogger{})
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			waitError := make(chan error)
			ready := make(chan struct{})
			go wireguard.Run(ctx, waitError, ready)

			const setupTimeout = 10 * time.Second
			timer := time.NewTimer(setupTimeout)
			select {
			case <-ready:
				timer.Stop()
			case err := <-waitError:
				cancel()
				t.Fatalf("setting up Wireguard: %s", err)
			case <-timer.C:
				cancel()
				t.Fatal("timed out setting up Wireguard")
			}

			cancel()
			err = <-waitError
			require.ErrorIs(t, err, context.Canceled)

			recorder.mutex.Lock()
			defer recorder.mutex.Unlock()
			assert.Equal(t, []string{"link delete", "rule delete"}, recorder.operations)
			assert.False(t, recorder.linkExistedOnRuleDel,
				"IP rule removed while the Wireguard link still existed, "+
					"which lets tunnel traffic leak out of the default route")

			_, err = netlinker.LinkByName(linkName)
			assert.Error(t, err, "Wireguard link should be deleted")
			rules, err := netlinker.RuleList(netlink.FamilyV4)
			require.NoError(t, err)
			for _, rule := range rules {
				assert.NotEqual(t, testCase.firewallMark, rule.Table,
					"IP rule for the Wireguard table should be removed")
			}
		})
	}
}
