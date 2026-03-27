package settings

import (
	"fmt"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
	"github.com/qdm12/log"
)

// Iptables contains settings to customize iptables.
type Iptables struct {
	LogLevel string
}

func (i Iptables) validate() (err error) {
	_, err = log.ParseLevel(i.LogLevel)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}

	return nil
}

func (i *Iptables) copy() (copied Iptables) {
	return Iptables{
		LogLevel: i.LogLevel,
	}
}

func (i *Iptables) overrideWith(other Iptables) {
	i.LogLevel = gosettings.OverrideWithComparable(i.LogLevel, other.LogLevel)
}

func (i *Iptables) setDefaults(globalLogLevel string) {
	defaultLevel := globalLogLevel
	if defaultLevel == log.LevelDebug.String() {
		// Given iptables debug logger is quite verbose, we only turn it to debug level
		// if it is explicitly asked to be at debug level; even if the global logger is
		// at the debug level, we keep iptables at info level by default.
		defaultLevel = log.LevelInfo.String()
	}
	i.LogLevel = gosettings.DefaultComparable(i.LogLevel, defaultLevel)
}

func (i Iptables) String() string {
	return i.toLinesNode().String()
}

func (i Iptables) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Iptables settings:")
	node.Appendf("Log level: %s", i.LogLevel)
	return node
}

func (i *Iptables) read(r *reader.Reader) (err error) {
	debugMode, err := r.BoolPtr("FIREWALL_DEBUG", reader.IsRetro("FIREWALL_IPTABLES_LOG_LEVEL"))
	if err != nil {
		return err
	}
	if debugMode != nil && *debugMode {
		i.LogLevel = log.LevelDebug.String()
	}
	i.LogLevel = r.String("FIREWALL_IPTABLES_LOG_LEVEL")
	return nil
}
