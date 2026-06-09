package restrictednet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"

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
}

func New(settings Settings) *Client {
	if err := settings.validate(); err != nil {
		panic(fmt.Sprintf("invalid settings: %v", err)) // programming error
	}
	dohServers := make([]provider.DoHServer, len(settings.UpstreamResolvers))
	for i, upstreamResolver := range settings.UpstreamResolvers {
		dohServers[i] = upstreamResolver.DoH
	}

	return &Client{
		outboundInterface: settings.DefaultInterface,
		ipv6Supported:     *settings.IPv6Supported,
		firewall:          settings.Firewall,
		dohServers:        dohServers,
	}
}

// OpenHTTPSByHostname opens an https connection through the firewall,
// valid for up to one second, to the hostname which in the format `host:port`.
// It first resolves the domain in hostname using DNS over HTTPS and then opens
// the restricted HTTPS connection to the resolved IP.
func (c *Client) OpenHTTPSByHostname(ctx context.Context, hostname string) (
	httpClient *http.Client, cleanup func() error, err error,
) {
	host, portStr, err := net.SplitHostPort(hostname)
	if err != nil {
		return nil, nil, fmt.Errorf("splitting host and port: %w", err)
	}
	resolvedIPs, err := c.ResolveName(ctx, host)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving name: %w", err)
	} else if len(resolvedIPs) == 0 {
		return nil, nil, fmt.Errorf("no IP address found for name %q", host)
	}

	portUint, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing port: %w", err)
	}
	port := uint16(portUint)

	errs := make([]error, 0, len(resolvedIPs))
	for _, ip := range resolvedIPs {
		addrPort := netip.AddrPortFrom(ip, port)
		httpClient, cleanup, err := c.OpenHTTPS(ctx, host, addrPort)
		if err != nil {
			errs = append(errs, fmt.Errorf("for %s: %w", ip, err))
			continue
		}
		return httpClient, cleanup, nil
	}

	return nil, nil, fmt.Errorf("opening HTTPS to %s: %w", hostname, errors.Join(errs...))
}
