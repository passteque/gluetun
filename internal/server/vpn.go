package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func newVPNHandler(ctx context.Context, looper VPNLooper,
	storage Storage, ipv6Supported bool, w warner,
) http.Handler {
	return &vpnHandler{
		ctx:           ctx,
		looper:        looper,
		storage:       storage,
		ipv6Supported: ipv6Supported,
		warner:        w,
	}
}

type vpnHandler struct {
	ctx           context.Context //nolint:containedctx
	looper        VPNLooper
	storage       Storage
	ipv6Supported bool
	warner        warner
}

func (h *vpnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.TrimPrefix(r.RequestURI, "/vpn")
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
		case http.MethodPut:
			h.patchSettings(w, r)
		default:
			errMethodNotSupported(w, r.Method)
		}
	case "/stats":
		switch r.Method {
		case http.MethodGet:
			h.getStats(w)
		default:
			errMethodNotSupported(w, r.Method)
		}
	default:
		errRouteNotSupported(w, r.RequestURI)
	}
}

func (h *vpnHandler) getStatus(w http.ResponseWriter) {
	status := h.looper.GetStatus()
	encoder := json.NewEncoder(w)
	data := statusWrapper{Status: string(status)}
	if err := encoder.Encode(data); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) setStatus(w http.ResponseWriter, r *http.Request) {
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
	outcome, err := h.looper.ApplyStatus(h.ctx, status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(outcomeWrapper{Outcome: outcome}); err != nil {
		h.warner.Warn(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) getSettings(w http.ResponseWriter) {
	settings := h.looper.GetSettings()
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(settings); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) patchSettings(w http.ResponseWriter, r *http.Request) {
	var overrideSettings settings.VPN
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&overrideSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = r.Body.Close()
	if err != nil {
		h.warner.Warn("closing body: " + err.Error())
	}

	updatedSettings := h.looper.GetSettings() // already copied
	updatedSettings.OverrideWith(overrideSettings)
	err = updatedSettings.Validate(h.storage, h.ipv6Supported, h.warner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	outcome := h.looper.SetSettings(h.ctx, updatedSettings)
	_, err = w.Write([]byte(outcome))
	if err != nil {
		h.warner.Warn("writing response: " + err.Error())
	}
}

// tunStats is the response for GET /v1/vpn/stats.
type tunStats struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
}

func (h *vpnHandler) getStats(w http.ResponseWriter) {
	iface := h.resolveTunInterface()
	rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface)
	txPath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface)

	rxData, err := os.ReadFile(rxPath)
	if err != nil {
		// Fallback: try the other common name if the configured one is missing
		fallback := "tun0"
		if iface == "tun0" {
			fallback = "wg0"
		}
		rxPath = fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", fallback)
		txPath = fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", fallback)
		rxData, err = os.ReadFile(rxPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("TUN interface %q (and fallback) not found or not up: %v", iface, err),
				http.StatusNotFound)
			return
		}
		iface = fallback
	}

	txData, err := os.ReadFile(txPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("reading tx_bytes for %s: %v", iface, err), http.StatusInternalServerError)
		return
	}

	rxBytes, err := strconv.ParseUint(strings.TrimSpace(string(rxData)), 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("parsing rx_bytes: %v", err), http.StatusInternalServerError)
		return
	}
	txBytes, err := strconv.ParseUint(strings.TrimSpace(string(txData)), 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("parsing tx_bytes: %v", err), http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(w)
	data := tunStats{
		Interface: iface,
		RxBytes:   rxBytes,
		TxBytes:   txBytes,
	}
	if err := encoder.Encode(data); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// resolveTunInterface returns the configured TUN/WG interface name
// based on the current VPN settings.
func (h *vpnHandler) resolveTunInterface() string {
	s := h.looper.GetSettings()
	switch s.Type {
	case vpn.OpenVPN:
		if s.OpenVPN.Interface != "" {
			return s.OpenVPN.Interface
		}
		return "tun0"
	case vpn.Wireguard, vpn.AmneziaWg:
		if s.Wireguard.Interface != "" {
			return s.Wireguard.Interface
		}
		if s.Type == vpn.AmneziaWg && s.AmneziaWg.Wireguard.Interface != "" {
			return s.AmneziaWg.Wireguard.Interface
		}
		return "wg0"
	default:
		return "tun0"
	}
}
