package restrictednet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/miekg/dns"
)

// ResolveName resolves the given host name to IP addresses using DoH servers,
// while opening temporary restrictive firewall rules for HTTPS traffic to DoH servers.
// The host must be a single well-formed domain name, without port or path.
func (c *Client) ResolveName(ctx context.Context, host string) (
	resolvedAddresses []netip.Addr, err error,
) {
	questionTypes := make([]uint16, 0, 2)
	if c.ipv6Supported {
		questionTypes = append(questionTypes, dns.TypeAAAA)
	}
	questionTypes = append(questionTypes, dns.TypeA)

	var addresses []netip.Addr
	errs := make([]error, 0, len(questionTypes))
	for _, questionType := range questionTypes {
		answerAddresses, err := c.resolveOneQuestionType(ctx, host, questionType)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		addresses = append(addresses, answerAddresses...)
	}

	switch {
	case len(addresses) > 0:
		return addresses, nil
	case len(errs) == 0:
		return nil, nil // no address found
	default: // errors
		return nil, fmt.Errorf("resolving host %q: %w", host, errors.Join(errs...))
	}
}

func (c *Client) resolveOneQuestionType(ctx context.Context,
	host string, questionType uint16,
) (addresses []netip.Addr, err error) {
	queryMessage := &dns.Msg{}
	queryMessage.SetQuestion(dns.Fqdn(host), questionType)
	queryWire, err := queryMessage.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS query: %w", err)
	}

	// Try every DoH server and every of each of their IP until we get a non-empty
	// successful response.
	errs := make([]error, 0)
	for _, dohServer := range c.dohServers {
		dohURL, err := url.Parse(dohServer.URL)
		if err != nil {
			errs = append(errs,
				fmt.Errorf("parsing DoH server URL %s: %w", dohServer.URL, err))
			continue
		}

		dohServerIPs := make([]netip.Addr, 0, len(dohServer.IPv4)+len(dohServer.IPv6))
		if c.ipv6Supported {
			// Prefer IPv6 addresses if IPv6 is supported
			dohServerIPs = append(dohServerIPs, dohServer.IPv6...)
		}
		dohServerIPs = append(dohServerIPs, dohServer.IPv4...)

		for _, dohServerIP := range dohServerIPs {
			responseMessage, err := c.doHQuery(ctx, queryWire, dohURL, dohServerIP)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("querying DoH server %q at %s: %w",
					dohServer.URL, dohServerIP, err))
				continue
			case responseMessage.Rcode != dns.RcodeSuccess:
				errs = append(errs, fmt.Errorf("querying DoH server %q at %s: DNS rcode %s",
					dohServer.URL, dohServerIP, dns.RcodeToString[responseMessage.Rcode]))
				continue
			}
			addresses := answersToNetipAddrs(responseMessage)
			if len(addresses) == 0 {
				continue
			}
			return addresses, nil
		}
	}

	if len(errs) == 0 {
		return nil, nil
	}

	return nil, fmt.Errorf("resolving %s %s: %w",
		dns.TypeToString[questionType], host, errors.Join(errs...))
}

func (c *Client) doHQuery(ctx context.Context, queryWire []byte,
	dohURL *url.URL, dohServerIP netip.Addr,
) (responseMessage *dns.Msg, err error) {
	httpClient, close, err := c.OpenHTTPS(dohURL.Hostname(), dohServerIP)
	if err != nil {
		return nil, fmt.Errorf("opening https connection: %w", err)
	}
	defer func() {
		closeErr := close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("cleaning up https connection: %w", closeErr)
		}
	}()

	requestBody := bytes.NewReader(queryWire)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL.String(), requestBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	err = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("closing response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response status code is %s, data: %s",
			response.Status, responseData)
	}

	responseMessage = new(dns.Msg)
	err = responseMessage.Unpack(responseData)
	if err != nil {
		return nil, fmt.Errorf("parsing DoH response: %w", err)
	}

	return responseMessage, nil
}

func answersToNetipAddrs(message *dns.Msg) (addresses []netip.Addr) {
	if message == nil {
		return nil
	}
	addresses = make([]netip.Addr, 0, len(message.Answer))
	for _, answer := range message.Answer {
		switch record := answer.(type) {
		case *dns.A:
			address, ok := netip.AddrFromSlice(record.A)
			if ok {
				addresses = append(addresses, address.Unmap())
			}
		case *dns.AAAA:
			address, ok := netip.AddrFromSlice(record.AAAA)
			if ok {
				addresses = append(addresses, address)
			}
		}
	}
	return addresses
}
