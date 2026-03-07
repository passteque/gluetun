package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/server/middlewares/auth"
	"github.com/qdm12/gluetun/internal/server/middlewares/log"
)

func newHandler(ctx context.Context, logger Logger, logging bool,
	authSettings auth.Settings,
	buildInfo models.BuildInformation,
	vpnLooper VPNLooper,
	pf PortForwarding,
	dnsLooper DNSLoop,
	updaterLooper UpdaterLooper,
	publicIPLooper PublicIPLoop,
	storage Storage,
	ipv6Supported bool,
) (httpHandler http.Handler, err error) {
	handler := &handler{}

	vpn := newVPNHandler(ctx, vpnLooper, storage, ipv6Supported, logger)
	openvpn := newOpenvpnHandler(ctx, vpnLooper, logger)
	dns := newDNSHandler(ctx, dnsLooper, logger)
	updater := newUpdaterHandler(ctx, updaterLooper, logger)
	publicip := newPublicIPHandler(publicIPLooper, logger)
	portForward := newPortForwardHandler(ctx, pf, logger)

	handler.v0 = newHandlerV0(ctx, logger, vpnLooper, dnsLooper, updaterLooper)
	handler.v1 = newHandlerV1(logger, buildInfo, vpn, openvpn, dns, updater, publicip, portForward)

	authMiddleware, err := auth.New(authSettings, logger)
	if err != nil {
		return nil, fmt.Errorf("creating auth middleware: %w", err)
	}

	middlewares := []func(http.Handler) http.Handler{
		authMiddleware,
		log.New(logger, logging),
	}
	httpHandler = handler
	for _, middleware := range middlewares {
		httpHandler = middleware(httpHandler)
	}
	return httpHandler, nil
}

type handler struct {
	v0 http.Handler
	v1 http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.TrimSuffix(r.RequestURI, "/")
	if !strings.HasPrefix(r.RequestURI, "/v1/") && r.RequestURI != "/v1" {
		h.v0.ServeHTTP(w, r)
		return
	}
	r.RequestURI = strings.TrimPrefix(r.RequestURI, "/v1")
	h.v1.ServeHTTP(w, r)
}
