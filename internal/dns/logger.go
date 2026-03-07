package dns

type Logger interface {
	Debug(s string)
	Info(s string)
	Infof(format string, args ...any)
	Warn(s string)
	Warnf(format string, args ...any)
	Error(s string)
}
