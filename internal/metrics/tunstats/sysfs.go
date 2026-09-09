package tunstats

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultSysfsNetPath = "/sys/class/net"

const (
	counterRxBytes = "rx_bytes"
	counterTxBytes = "tx_bytes"
)

// readInterfaceStats reads the cumulative received and sent bytes of
// the given network interface from the sysfs statistics.
func (c *Collector) readInterfaceStats(interfaceName string) (
	rxBytes, txBytes uint64, err error,
) {
	rxBytes, err = c.readSysfsCounter(c.counterPath(interfaceName, counterRxBytes))
	if err != nil {
		return 0, 0, fmt.Errorf("reading %s: %w", counterRxBytes, err)
	}
	txBytes, err = c.readSysfsCounter(c.counterPath(interfaceName, counterTxBytes))
	if err != nil {
		return 0, 0, fmt.Errorf("reading %s: %w", counterTxBytes, err)
	}
	return rxBytes, txBytes, nil
}

func (c *Collector) readSysfsCounter(counterPath string) (value uint64, err error) {
	data, err := os.ReadFile(counterPath)
	if err != nil {
		return 0, fmt.Errorf("reading interface statistics: %w", err)
	}
	const (
		decimalBase = 10
		uint64Bits  = 64
	)
	value, err = strconv.ParseUint(strings.TrimSpace(string(data)), decimalBase, uint64Bits)
	if err != nil {
		return 0, fmt.Errorf("parsing interface statistics: %w", err)
	}
	return value, nil
}

func (c *Collector) counterPath(interfaceName, counterName string) (path string) {
	return filepath.Join(c.sysfsNetPath, interfaceName, "statistics", counterName)
}
