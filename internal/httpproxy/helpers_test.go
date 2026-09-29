package httpproxy

var _ Logger = (*testLogger)(nil)

type testLogger struct{}

func (t *testLogger) Info(string)  {}
func (t *testLogger) Error(string) {}
func (t *testLogger) Debug(string) {}
func (t *testLogger) Warn(string)  {}
