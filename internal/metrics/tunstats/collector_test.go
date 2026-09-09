package tunstats

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubVPNLooper struct {
	vpnSettings settings.VPN
}

func (s stubVPNLooper) GetSettings() (vpnSettings settings.VPN) {
	return s.vpnSettings
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
	err := New(registry, stubVPNLooper{})
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

			sysfsNetPath := t.TempDir()
			createInterfaceStats(t, sysfsNetPath, testCase.interfaceName,
				testCase.rxBytes, testCase.txBytes)

			registry := prometheus.NewRegistry()
			require.NoError(t, newCollector(registry,
				stubVPNLooper{vpnSettings: testCase.vpnSettings}, sysfsNetPath))

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

func Test_New_Gather_NoMetrics(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnSettings settings.VPN
	}{
		"interface absent": {
			vpnSettings: settings.VPN{
				Type:    vpn.OpenVPN,
				OpenVPN: settings.OpenVPN{Interface: "tun0"},
			},
		},
		"unknown vpn type": {
			vpnSettings: settings.VPN{Type: "unknown"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Empty sysfs: the interface is not present.
			sysfsNetPath := t.TempDir()

			registry := prometheus.NewRegistry()
			require.NoError(t, newCollector(registry,
				stubVPNLooper{vpnSettings: testCase.vpnSettings}, sysfsNetPath))

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)

			assert.Nil(t, findMetricFamily(metricFamilies, metricRxBytesName))
			assert.Nil(t, findMetricFamily(metricFamilies, metricTxBytesName))
		})
	}
}
