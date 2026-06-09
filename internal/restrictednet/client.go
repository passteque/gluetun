package restrictednet

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/qdm12/dns/v2/pkg/provider"
)

// Client is a client for making restricted network requests,
// such as opening temporary firewall rules for HTTPS connections.
// It is not meant to be high performance, although it can be used for
// multiple requests and concurrently.
type Client struct {
	outboundInterface string
	ipv6Supported     bool
	firewall          Firewall
	dohServers        []provider.DoHServer
	baseTransport     *http.Transport
	httpsPort         uint16
}

func New(settings Settings) *Client {
	settings.setDefaults()
	if err := settings.validate(); err != nil {
		panic(fmt.Sprintf("invalid settings: %v", err)) // programming error
	}
	dohServers := make([]provider.DoHServer, len(settings.UpstreamResolvers))
	for i, upstreamResolver := range settings.UpstreamResolvers {
		dohServers[i] = upstreamResolver.DoH
	}

	const defaultHTTPSPort = 443
	return &Client{
		outboundInterface: settings.DefaultInterface,
		ipv6Supported:     *settings.IPv6Supported,
		firewall:          settings.Firewall,
		dohServers:        dohServers,
		baseTransport:     settings.BaseTransport,
		httpsPort:         defaultHTTPSPort,
	}
}

func (c *Client) OpenHTTPSByDomain(ctx context.Context, domain string) (
	httpClient *http.Client, cleanup func() error, err error,
) {
	resolvedIPs, err := c.ResolveName(ctx, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving name: %w", err)
	} else if len(resolvedIPs) == 0 {
		return nil, nil, fmt.Errorf("no IP address found for name %q", domain)
	}

	errs := make([]error, 0, len(resolvedIPs))
	for _, ip := range resolvedIPs {
		httpClient, cleanup, err := c.OpenHTTPS(ctx, domain, ip)
		if err != nil {
			errs = append(errs, fmt.Errorf("for %s: %w", ip, err))
			continue
		}
		return httpClient, cleanup, nil
	}

	return nil, nil, fmt.Errorf("opening HTTPS to %s: %w", domain, errors.Join(errs...))
}
