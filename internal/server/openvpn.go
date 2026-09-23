package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func newOpenvpnHandler(ctx context.Context, looper VPNLooper, w warner) http.Handler {
	return &openvpnHandler{
		ctx:    ctx,
		looper: looper,
		warner: w,
	}
}

type openvpnHandler struct {
	ctx    context.Context //nolint:containedctx
	looper VPNLooper
	warner warner
}

func (h *openvpnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.TrimPrefix(r.RequestURI, "/openvpn")
	switch r.RequestURI {
	case "/status":
		switch r.Method {
		case http.MethodGet:
			h.getStatus(w)
		case http.MethodPut:
			h.setStatus(w, r)
		default:
			errMethodNotSupported(w, r.Method)
		}
	case "/settings":
		switch r.Method {
		case http.MethodGet:
			h.getSettings(w)
		default:
			errMethodNotSupported(w, r.Method)
		}
	case "/portforwarded": // TODO v4 remove
		switch r.Method {
		case http.MethodGet:
			http.Redirect(w, r, "/v1/portforward", http.StatusMovedPermanently)
		default:
			errMethodNotSupported(w, r.Method)
		}
	default:
		errRouteNotSupported(w, r.RequestURI)
	}
}

func (h *openvpnHandler) getStatus(w http.ResponseWriter) {
	vpnStatus := h.looper.GetStatus()
	openVPNStatus := vpnStatus
	if vpnStatus != constants.Stopped {
		vpnSettings := h.looper.GetSettings()
		if vpnSettings.Type != vpn.OpenVPN {
			openVPNStatus = constants.Stopped
		}
	}
	encoder := json.NewEncoder(w)
	data := statusWrapper{Status: string(openVPNStatus)}
	if err := encoder.Encode(data); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *openvpnHandler) setStatus(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var data statusWrapper
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := data.getStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var outcome string
	loopSettings := h.looper.GetSettings()
	if status == constants.Running && loopSettings.Type != vpn.OpenVPN {
		// Stop Wireguard if it was the selected type and we want to start OpenVPN
		loopSettings.Type = vpn.OpenVPN
		outcome = h.looper.SetSettings(h.ctx, loopSettings)
	} else {
		// Only update status of OpenVPN
		outcome, err = h.looper.ApplyStatus(h.ctx, status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(outcomeWrapper{Outcome: outcome}); err != nil {
		h.warner.Warn(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (h *openvpnHandler) getSettings(w http.ResponseWriter) {
	vpnSettings := h.looper.GetSettings()
	settings := vpnSettings.OpenVPN
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(settings); err != nil { //nolint:gosec
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
