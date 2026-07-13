package firewall

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type temporaryRuleCall struct {
	interfaceName string
	mark          uint32
	remove        bool
	contextErr    error
}

type temporaryFirewallImpl struct {
	firewallImpl
	addErrorInterface           string
	addErrorAfterApplyInterface string
	onAddErrorAfterApply        func()
	removeFailures              uint
	calls                       []temporaryRuleCall
	activeRules                 map[string]uint
	maxActiveRules              uint
}

type temporaryLogger struct{}

func (temporaryLogger) Debug(string) {}
func (temporaryLogger) Info(string) {}
func (temporaryLogger) Warn(string) {}
func (temporaryLogger) Error(string) {}

func (f *temporaryFirewallImpl) AcceptOutputMarked(ctx context.Context, _, interfaceName string,
	_ netip.Addr, _ uint16, mark uint32, remove bool,
) error {
	f.calls = append(f.calls, temporaryRuleCall{
		interfaceName: interfaceName,
		mark:          mark,
		remove:        remove,
		contextErr:    ctx.Err(),
	})
	if !remove && interfaceName == f.addErrorInterface {
		return errors.New("add error")
	}
	if remove && f.removeFailures > 0 {
		f.removeFailures--
		return errors.New("remove error")
	}
	if f.activeRules == nil {
		f.activeRules = make(map[string]uint)
	}
	if remove {
		if f.activeRules[interfaceName] <= 1 {
			delete(f.activeRules, interfaceName)
		} else {
			f.activeRules[interfaceName]--
		}
		return nil
	}

	f.activeRules[interfaceName]++
	var activeRules uint
	for _, count := range f.activeRules {
		activeRules += count
	}
	if activeRules > f.maxActiveRules {
		f.maxActiveRules = activeRules
	}
	if interfaceName == f.addErrorAfterApplyInterface {
		f.onAddErrorAfterApply()
		return errors.New("add error after apply")
	}
	return nil
}

func newTemporaryTestConfig(impl firewallImpl, interfaces ...string) *Config {
	defaultRoutes := make([]routing.DefaultRoute, len(interfaces))
	for i, interfaceName := range interfaces {
		defaultRoutes[i] = routing.DefaultRoute{
			NetInterface: interfaceName,
			Family:       netlink.FamilyV4,
		}
	}
	return &Config{
		impl:          impl,
		enabled:       true,
		defaultRoutes: defaultRoutes,
	}
}

func temporaryTestConnection() models.Connection {
	return models.Connection{
		IP:       netip.MustParseAddr("198.51.100.10"),
		Port:     443,
		Protocol: constants.TCP,
	}
}

func Test_Config_TempAllowConnection_partialAdditionRollback(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{addErrorInterface: "eth1"}
	config := newTemporaryTestConfig(impl, "eth0", "eth1")

	remove, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())

	require.Error(t, err)
	assert.Nil(t, remove)
	assert.ErrorContains(t, err, "allowing temporary output connection: add error")
	assert.Empty(t, impl.activeRules)
	assert.Empty(t, config.temporaryRules)
	require.Len(t, impl.calls, 4)
	assert.Equal(t, []temporaryRuleCall{
		{interfaceName: "eth0", mark: 51820},
		{interfaceName: "eth1", mark: 51820},
		{interfaceName: "eth0", mark: 51820, remove: true},
		{interfaceName: "eth1", mark: 51820, remove: true},
	}, impl.calls)
}

func Test_Config_TempAllowConnection_appendErrorAfterApplyIsTrackedAndCleaned(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	var config *Config
	trackedBeforeError := false
	impl := &temporaryFirewallImpl{
		addErrorAfterApplyInterface: "eth0",
		onAddErrorAfterApply: func() {
			cancel()
			require.Len(t, config.temporaryRules, 1)
			for rules := range config.temporaryRules {
				assert.Equal(t, []string{"eth0"}, rules.interfaces)
				trackedBeforeError = true
			}
		},
	}
	config = newTemporaryTestConfig(impl, "eth0")

	remove, err := config.TempAllowConnection(ctx, temporaryTestConnection())

	require.Error(t, err)
	assert.Nil(t, remove)
	assert.ErrorContains(t, err, "allowing temporary output connection: add error after apply")
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	assert.True(t, trackedBeforeError)
	assert.Empty(t, impl.activeRules)
	assert.Empty(t, config.temporaryRules)
	require.Len(t, impl.calls, 2)
	assert.Equal(t, []temporaryRuleCall{
		{interfaceName: "eth0", mark: 51820},
		{interfaceName: "eth0", mark: 51820, remove: true},
	}, impl.calls)
	assert.NoError(t, impl.calls[1].contextErr)
}

func Test_Config_TempAllowConnection_deletionFailureCanBeRetried(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{removeFailures: 1}
	config := newTemporaryTestConfig(impl, "eth0", "eth1")
	remove, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())
	require.NoError(t, err)

	err = remove(t.Context())
	require.Error(t, err)
	assert.ErrorContains(t, err, "remove error")
	assert.Equal(t, map[string]uint{"eth0": 1}, impl.activeRules)
	assert.Len(t, config.temporaryRules, 1)

	require.NoError(t, remove(t.Context()))
	assert.Empty(t, impl.activeRules)
	assert.Empty(t, config.temporaryRules)
	require.Len(t, impl.calls, 5)
	assert.Equal(t, temporaryRuleCall{
		interfaceName: "eth0",
		mark:          51820,
		remove:        true,
	}, impl.calls[4])
	callCount := len(impl.calls)
	require.NoError(t, remove(t.Context()))
	assert.Len(t, impl.calls, callCount)
}

func Test_Config_TempAllowConnection_cancellationStillTearsDown(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{}
	config := newTemporaryTestConfig(impl, "eth0")
	ctx, cancel := context.WithCancel(t.Context())
	remove, err := config.TempAllowConnection(ctx, temporaryTestConnection())
	require.NoError(t, err)
	cancel()

	require.NoError(t, remove(ctx))
	assert.Empty(t, impl.activeRules)
	require.Len(t, impl.calls, 2)
	assert.NoError(t, impl.calls[1].contextErr)
}

func Test_Config_TempAllowConnection_reconnectSweepsFailedRulesBeforeAdding(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{removeFailures: 1}
	config := newTemporaryTestConfig(impl, "eth0")
	firstRemove, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())
	require.NoError(t, err)
	require.Error(t, firstRemove(t.Context()))

	secondRemove, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())
	require.NoError(t, err)
	assert.Equal(t, uint(1), impl.maxActiveRules)
	assert.Equal(t, map[string]uint{"eth0": 1}, impl.activeRules)
	require.NoError(t, secondRemove(t.Context()))
	assert.Empty(t, impl.activeRules)
	assert.Empty(t, config.temporaryRules)
}

func Test_Config_TempAllowConnection_onlyMarkedTrafficIsAllowed(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{}
	config := newTemporaryTestConfig(impl, "eth0")
	remove, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, remove(t.Context())) })

	require.Len(t, impl.calls, 1)
	assert.Equal(t, uint32(51820), impl.calls[0].mark)
	assert.NotEqual(t, uint32(0), impl.calls[0].mark,
		"unmarked traffic to the same destination must not match the allowance")
}

func Test_Config_SetEnabled_shutdownSweepsTemporaryRulesWithCanceledContext(t *testing.T) {
	t.Parallel()

	impl := &temporaryFirewallImpl{}
	config := newTemporaryTestConfig(impl, "eth0")
	config.logger = temporaryLogger{}
	restoreContextErr := errors.New("restore was not called")
	config.restore = func(ctx context.Context) {
		restoreContextErr = ctx.Err()
	}
	_, err := config.TempAllowConnection(t.Context(), temporaryTestConnection())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.NoError(t, config.SetEnabled(ctx, false))
	assert.Empty(t, impl.activeRules)
	assert.Empty(t, config.temporaryRules)
	assert.NoError(t, restoreContextErr)
	assert.False(t, config.enabled)
	require.Len(t, impl.calls, 2)
	assert.NoError(t, impl.calls[1].contextErr)
}

func Test_defaultRouteInterfacesForIP(t *testing.T) {
	t.Parallel()

	defaultRoutes := []routing.DefaultRoute{
		{NetInterface: "eth0", Family: netlink.FamilyV4},
		{NetInterface: "eth0", Family: netlink.FamilyV4},
		{NetInterface: "eth1", Family: netlink.FamilyV4},
		{NetInterface: "eth2", Family: netlink.FamilyV6},
	}
	testCases := map[string]struct {
		ip         netip.Addr
		interfaces []string
	}{
		"ipv4": {
			ip:         netip.MustParseAddr("100.100.100.100"),
			interfaces: []string{"eth0", "eth1"},
		},
		"ipv6": {
			ip:         netip.MustParseAddr("2001:db8::53"),
			interfaces: []string{"eth2"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			interfaces := defaultRouteInterfacesForIP(defaultRoutes, testCase.ip)
			assert.Equal(t, testCase.interfaces, interfaces)
		})
	}
}
