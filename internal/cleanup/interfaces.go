package cleanup

type Logger interface {
	Debug(string)
	Error(string)
}
