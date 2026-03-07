package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func newPortForwardHandler(ctx context.Context,
	portForward PortForwarding, warner warner,
) http.Handler {
	return &portForwardHandler{
		ctx:         ctx,
		portForward: portForward,
		warner:      warner,
	}
}

type portForwardHandler struct {
	ctx         context.Context //nolint:containedctx
	portForward PortForwarding
	warner      warner
}

func (h *portForwardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getPortForwarded(w)
	case http.MethodPut:
		h.setPortForwarded(w, r)
	default:
		errMethodNotSupported(w, r.Method)
	}
}

func (h *portForwardHandler) getPortForwarded(w http.ResponseWriter) {
	ports := h.portForward.GetPortsForwarded()
	encoder := json.NewEncoder(w)
	var data any
	switch len(ports) {
	case 0:
		data = portWrapper{Port: 0} // TODO v4 change to portsWrapper
	case 1:
		data = portWrapper{Port: ports[0]} // TODO v4 change to portsWrapper
	default:
		data = portsWrapper{Ports: ports}
	}

	err := encoder.Encode(data)
	if err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *portForwardHandler) setPortForwarded(w http.ResponseWriter, r *http.Request) {
	var data portsWrapper

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		h.warner.Warn(fmt.Sprintf("failed setting forwarded ports: %s", err))
		http.Error(w, "failed setting forwarded ports", http.StatusBadRequest)
		return
	}

	err = h.portForward.SetPortsForwarded(data.Ports)
	if err != nil {
		h.warner.Warn(fmt.Sprintf("failed setting forwarded ports: %s", err))
		http.Error(w, "failed setting forwarded ports", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
