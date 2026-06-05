package restrictednet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// OpenHTTPS opens temporary restrictive firewall output for one HTTPS destination.
// The returned cleanup function must be called to remove the temporary firewall rule and close connections.
func (c *Client) OpenHTTPS(destinationTLSName string, destinationIP netip.Addr,
) (httpClient *http.Client, cleanup func() error, err error) {
	listener, sourceAddrPort, err := bindSourcePort(destinationIP)
	if err != nil {
		return nil, nil, fmt.Errorf("binding source port: %w", err)
	}

	const httpsPort = 443
	destinationAddrPort := netip.AddrPortFrom(destinationIP, httpsPort)

	const remove = false
	ctx := context.Background() // it's a quick firewall change, worth not passing a context
	err = c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
		sourceAddrPort, destinationAddrPort, remove)
	if err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("allowing output traffic through firewall: %w", err)
	}

	httpClient = newHTTPSClient(destinationTLSName, destinationIP, sourceAddrPort)
	cleanup = func() error {
		var errs []error
		httpClient.CloseIdleConnections()
		const remove = true
		err := c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
			sourceAddrPort, destinationAddrPort, remove)
		if err != nil {
			errs = append(errs, fmt.Errorf("removing output traffic rule: %w", err))
		}
		err = listener.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("closing listener: %w", err))
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return nil
	}
	return httpClient, cleanup, nil
}

func newHTTPSClient(destinationTLSName string,
	destinationIP netip.Addr, sourceAddress netip.AddrPort,
) *http.Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert
	httpTransport.Proxy = nil
	httpTransport.MaxIdleConns = 1
	httpTransport.MaxIdleConnsPerHost = 1
	httpTransport.IdleConnTimeout = time.Second
	httpTransport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: destinationTLSName,
	}
	httpTransport.DialContext = newBoundDialContext(destinationIP, sourceAddress)

	const timeout = 5 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
}

func newBoundDialContext(destinationAddress netip.Addr,
	sourceAddress netip.AddrPort,
) func(ctx context.Context, network, _ string) (net.Conn, error) {
	const httpsPort = 443
	destinationAddrPort := netip.AddrPortFrom(destinationAddress, httpsPort).String()
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		const timeout = 2 * time.Second
		dialer := &net.Dialer{Timeout: timeout}
		dialer.LocalAddr = net.TCPAddrFromAddrPort(sourceAddress)
		connection, err := dialer.DialContext(ctx, network, destinationAddrPort)
		if err != nil {
			return nil, fmt.Errorf("%s dialing %s: %w", network, destinationAddrPort, err)
		}
		return connection, nil
	}
}

func bindSourcePort(destinationIP netip.Addr) (
	listener net.Listener, sourceAddr netip.AddrPort, err error,
) {
	var bindAddr netip.Addr
	if destinationIP.Is4() {
		bindAddr = netip.AddrFrom4([4]byte{})
	} else {
		bindAddr = netip.AddrFrom16([16]byte{})
	}

	listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(
		netip.AddrPortFrom(bindAddr, 0)))
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("binding TCP port: %w", err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr) //nolint:forcetypeassert
	sourceAddr = tcpAddr.AddrPort()

	return listener, sourceAddr, nil
}
