package nftables

type Logger interface {
	Warnf(format string, args ...any)
}
