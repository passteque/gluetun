package prometheus

import (
	"fmt"
)

type promLogger struct {
	logger Logger
}

func (p *promLogger) Println(v ...any) {
	message := fmt.Sprint(v...)
	p.logger.Error(message)
}
