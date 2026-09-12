package tunstats

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_readInterfaceStats(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rxFile      string // the empty string means the file is not created
		txFile      string
		expectedRx  uint64
		expectedTx  uint64
		errContains string
	}{
		"valid": {
			rxFile:     "1234\n",
			txFile:     "5678\n",
			expectedRx: 1234,
			expectedTx: 5678,
		},
		"zero_values": {
			rxFile:     "0\n",
			txFile:     "0\n",
			expectedRx: 0,
			expectedTx: 0,
		},
		"missing_rx_file": {
			rxFile:      "",
			txFile:      "5678\n",
			errContains: "reading rx_bytes",
		},
		"missing_tx_file": {
			rxFile:      "1234\n",
			txFile:      "",
			errContains: "reading tx_bytes",
		},
		"invalid_rx_content": {
			rxFile:      "notanumber\n",
			txFile:      "5678\n",
			errContains: "parsing rx_bytes",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			const interfaceName = "tun0"
			sysfsNetPath := t.TempDir()
			statsDir := filepath.Join(sysfsNetPath, interfaceName, "statistics")
			require.NoError(t, os.MkdirAll(statsDir, 0o755))
			if testCase.rxFile != "" {
				require.NoError(t, os.WriteFile(
					filepath.Join(statsDir, counterRxBytes),
					[]byte(testCase.rxFile), 0o600))
			}
			if testCase.txFile != "" {
				require.NoError(t, os.WriteFile(
					filepath.Join(statsDir, counterTxBytes),
					[]byte(testCase.txFile), 0o600))
			}

			collector := &Collector{sysfsNetPath: sysfsNetPath}
			rxBytes, txBytes, err := collector.readInterfaceStats(interfaceName)

			if testCase.errContains != "" {
				assert.ErrorContains(t, err, testCase.errContains)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedRx, rxBytes)
			assert.Equal(t, testCase.expectedTx, txBytes)
		})
	}
}
