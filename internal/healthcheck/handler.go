package healthcheck

import (
	"errors"
	"net/http"
	"sync"
)

type handler struct {
	healthErr   error
	healthErrMu sync.RWMutex
	logger      Logger
}

func newHandler(logger Logger) *handler {
	return &handler{
		healthErr: errors.New("healthcheck did not run yet"),
		logger:    logger,
	}
}

func (h *handler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(responseWriter, "method not supported for healthcheck", http.StatusBadRequest)
		return
	}
	if err := h.getErr(); err != nil {
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	responseWriter.WriteHeader(http.StatusOK)
}

func (h *handler) setErr(err error) {
	h.healthErrMu.Lock()
	defer h.healthErrMu.Unlock()
	h.healthErr = err
}

func (h *handler) getErr() (err error) {
	h.healthErrMu.RLock()
	defer h.healthErrMu.RUnlock()
	return h.healthErr
}
