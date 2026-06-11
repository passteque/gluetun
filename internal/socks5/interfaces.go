package socks5

type Logger interface {
	Infof(format string, a ...interface{})
	Warnf(format string, a ...interface{})
}
