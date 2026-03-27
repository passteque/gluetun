package command

type Logger interface {
	Info(s string)
	Error(s string)
}
