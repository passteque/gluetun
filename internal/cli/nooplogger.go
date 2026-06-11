package cli

type noopLogger struct{}

func newNoopLogger() *noopLogger {
	return new(noopLogger)
}

func (l *noopLogger) Info(string)          {}
func (l *noopLogger) Infof(string, ...any) {}
func (l *noopLogger) Warn(string)          {}
func (l *noopLogger) Warnf(string, ...any) {}
