package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/qdm12/gluetun/internal/portforward"
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
	data := portsWrapper{Ports: ports}
	if len(ports) > 0 {
		data.Port = ports[0] // TODO v4 remove
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
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&data)
	if err != nil {
		h.warner.Warn(fmt.Sprintf("failed setting forwarded ports: %s", err))
		http.Error(w, "failed setting forwarded ports", http.StatusBadRequest)
		return
	}

	err = h.portForward.SetPortsForwarded(data.Ports)
	if err != nil {
		err = fmt.Errorf("setting forwarded ports: %w", err)
		h.warner.Warn(err.Error())
		if errors.Is(err, portforward.ErrServiceNotRunning) {
			// The run loop starts a service by itself, so the ports can be asked
			// for again once it has done so, which the status says.
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "failed setting forwarded ports", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
