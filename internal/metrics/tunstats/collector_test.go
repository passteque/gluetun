package tunstats

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

// warningMessageMatcher is a gomock matcher matching a warning message
// containing the given substring.
type warningMessageMatcher struct {
	contains string
}

func (m warningMessageMatcher) Matches(x any) bool {
	message, ok := x.(string)
	return ok && strings.Contains(message, m.contains)
}

func (m warningMessageMatcher) String() string {
	return fmt.Sprintf("warning message containing %q", m.contains)
}

func createInterfaceStats(t *testing.T, sysfsNetPath, interfaceName,
	rxBytes, txBytes string,
) {
	t.Helper()
	statsDir := filepath.Join(sysfsNetPath, interfaceName, "statistics")
	require.NoError(t, os.MkdirAll(statsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(statsDir, counterRxBytes),
		[]byte(rxBytes+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(statsDir, counterTxBytes),
		[]byte(txBytes+"\n"), 0o600))
}

func findMetricFamily(metricFamilies []*dto.MetricFamily,
	name string,
) (metricFamily *dto.MetricFamily) {
	for _, candidate := range metricFamilies {
		if candidate.GetName() == name {
			return candidate
		}
	}
	return nil
}

func Test_New(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	err := New(registry, NewMockVPNLooper(nil), NewMockLinkLister(nil),
		NewMockLogger(nil))
	assert.NoError(t, err)
}

func Test_New_Gather(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnSettings   settings.VPN
		interfaceName string
		rxBytes       string
		txBytes       string
		expectedRx    float64
		expectedTx    float64
	}{
		"openvpn": {
			vpnSettings: settings.VPN{
				Type:    vpn.OpenVPN,
				OpenVPN: settings.OpenVPN{Interface: "tun0"},
			},
			interfaceName: "tun0",
			rxBytes:       "1234",
			txBytes:       "5678",
			expectedRx:    1234,
			expectedTx:    5678,
		},
		"wireguard": {
			vpnSettings: settings.VPN{
				Type:      vpn.Wireguard,
				Wireguard: settings.Wireguard{Interface: "wg0"},
			},
			interfaceName: "wg0",
			rxBytes:       "100",
			txBytes:       "200",
			expectedRx:    100,
			expectedTx:    200,
		},
		"amneziawg": {
			vpnSettings: settings.VPN{
				Type: vpn.AmneziaWg,
				AmneziaWg: settings.AmneziaWg{
					Wireguard: settings.Wireguard{Interface: "awg0"},
				},
			},
			interfaceName: "awg0",
			rxBytes:       "300",
			txBytes:       "400",
			expectedRx:    300,
			expectedTx:    400,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockVPNLooper := NewMockVPNLooper(ctrl)
			mockVPNLooper.EXPECT().GetSettings().Return(testCase.vpnSettings)
			mockLinkLister := NewMockLinkLister(ctrl)
			mockLinkLister.EXPECT().LinkByName(testCase.interfaceName).
				Return(netlink.Link{}, nil)
			mockLogger := NewMockLogger(ctrl)

			sysfsNetPath := t.TempDir()
			createInterfaceStats(t, sysfsNetPath, testCase.interfaceName,
				testCase.rxBytes, testCase.txBytes)

			registry := prometheus.NewRegistry()
			require.NoError(t, newCollector(registry, mockVPNLooper,
				mockLinkLister, mockLogger, sysfsNetPath))

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)

			rxMetricFamily := findMetricFamily(metricFamilies, metricRxBytesName)
			require.NotNil(t, rxMetricFamily)
			assert.Equal(t, testCase.expectedRx, rxMetricFamily.Metric[0].Counter.GetValue())
			assert.Equal(t, testCase.interfaceName, rxMetricFamily.Metric[0].Label[0].GetValue())

			txMetricFamily := findMetricFamily(metricFamilies, metricTxBytesName)
			require.NotNil(t, txMetricFamily)
			assert.Equal(t, testCase.expectedTx, txMetricFamily.Metric[0].Counter.GetValue())
		})
	}
}

func Test_New_Gather_Link_Absent(t *testing.T) {
	t.Parallel()

	const interfaceName = "tun0"

	ctrl := gomock.NewController(t)
	mockVPNLooper := NewMockVPNLooper(ctrl)
	mockVPNLooper.EXPECT().GetSettings().Return(settings.VPN{
		Type:    vpn.OpenVPN,
		OpenVPN: settings.OpenVPN{Interface: interfaceName},
	})
	mockLinkLister := NewMockLinkLister(ctrl)
	mockLinkLister.EXPECT().LinkByName(interfaceName).
		Return(netlink.Link{}, errors.New("link not found"))
	mockLogger := NewMockLogger(ctrl)

	// The link does not exist, so 0 is written to the metrics
	// without any warning, and the sysfs is not read.
	sysfsNetPath := t.TempDir()

	registry := prometheus.NewRegistry()
	require.NoError(t, newCollector(registry, mockVPNLooper, mockLinkLister,
		mockLogger, sysfsNetPath))

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	rxMetricFamily := findMetricFamily(metricFamilies, metricRxBytesName)
	require.NotNil(t, rxMetricFamily)
	assert.Equal(t, float64(0), rxMetricFamily.Metric[0].Counter.GetValue())

	txMetricFamily := findMetricFamily(metricFamilies, metricTxBytesName)
	require.NotNil(t, txMetricFamily)
	assert.Equal(t, float64(0), txMetricFamily.Metric[0].Counter.GetValue())
}

func Test_New_Gather_Read_Error(t *testing.T) {
	t.Parallel()

	const interfaceName = "tun0"

	ctrl := gomock.NewController(t)
	mockVPNLooper := NewMockVPNLooper(ctrl)
	mockVPNLooper.EXPECT().GetSettings().Return(settings.VPN{
		Type:    vpn.OpenVPN,
		OpenVPN: settings.OpenVPN{Interface: interfaceName},
	})
	mockLinkLister := NewMockLinkLister(ctrl)
	mockLinkLister.EXPECT().LinkByName(interfaceName).Return(netlink.Link{}, nil)
	mockLogger := NewMockLogger(ctrl)
	mockLogger.EXPECT().Warn(warningMessageMatcher{
		contains: "reading interface statistics for " + interfaceName,
	})

	// The link exists, but the sysfs statistics are missing, so no
	// metric is emitted and a warning is logged.
	sysfsNetPath := t.TempDir()

	registry := prometheus.NewRegistry()
	require.NoError(t, newCollector(registry, mockVPNLooper, mockLinkLister,
		mockLogger, sysfsNetPath))

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	assert.Nil(t, findMetricFamily(metricFamilies, metricRxBytesName))
	assert.Nil(t, findMetricFamily(metricFamilies, metricTxBytesName))
}
