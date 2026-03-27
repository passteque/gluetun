package amneziawg

//go:generate mockgen -destination=log_mock_test.go -package amneziawg . Logger

type Logger interface {
	Debug(s string)
	Debugf(format string, args ...interface{})
	Info(s string)
	Error(s string)
	Errorf(format string, args ...interface{})
}
