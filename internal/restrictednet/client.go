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
	ipv6Supported     bool
	firewall          Firewall
	outboundInterface string
	dohServers        []provider.DoHServer
	httpsPort         uint16
}

func New(firewall Firewall, defaultInterface string, ipv6Supported bool,
	upstreamResolvers []provider.Provider,
) *Client {
	if len(upstreamResolvers) == 0 {
		panic("no upstream resolvers provided") // programming error
	}
	dohServers := make([]provider.DoHServer, len(upstreamResolvers))
	for i, upstreamResolver := range upstreamResolvers {
		dohServers[i] = upstreamResolver.DoH
	}

	const defaultHTTPSPort = 443
	return &Client{
		firewall:          firewall,
		outboundInterface: defaultInterface,
		ipv6Supported:     ipv6Supported,
		dohServers:        dohServers,
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
