package boringpoll

type Logger interface {
	Infof(format string, args ...any)
	Debugf(format string, args ...any)
}
