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
func (c *Client) OpenHTTPS(ctx context.Context, destinationTLSName string, destinationIP netip.Addr,
) (httpClient *http.Client, cleanup func() error, err error) {
	connection, sourceAddrPort, err := bindSourceConnection(ctx, destinationIP)
	if err != nil {
		return nil, nil, fmt.Errorf("binding source port: %w", err)
	}

	const httpsPort = 443
	destinationAddrPort := netip.AddrPortFrom(destinationIP, httpsPort)

	const remove = false
	err = c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
		sourceAddrPort, destinationAddrPort, remove)
	if err != nil {
		_ = connection.Close()
		return nil, nil, fmt.Errorf("allowing output traffic through firewall: %w", err)
	}

	httpClient = newHTTPSClient(destinationTLSName, connection)
	cleanup = func() error {
		var errs []error
		httpClient.CloseIdleConnections()
		const remove = true
		err := c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
			sourceAddrPort, destinationAddrPort, remove)
		if err != nil {
			errs = append(errs, fmt.Errorf("removing output traffic rule: %w", err))
		}
		err = connection.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("closing connection: %w", err))
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return nil
	}
	return httpClient, cleanup, nil
}

func newHTTPSClient(destinationTLSName string,
	connection net.Conn,
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
	httpTransport.DialContext = newConnectionDialContext(connection)

	const timeout = 5 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
}

func newConnectionDialContext(connection net.Conn) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return connection, nil
	}
}

func bindSourceConnection(ctx context.Context, destinationIP netip.Addr) (
	connection net.Conn, sourceAddr netip.AddrPort, err error,
) {
	var bindAddr netip.Addr
	if destinationIP.Is4() {
		bindAddr = netip.AddrFrom4([4]byte{})
	} else {
		bindAddr = netip.AddrFrom16([16]byte{})
	}

	const httpsPort = 443
	destinationAddrPort := netip.AddrPortFrom(destinationIP, httpsPort)
	dialer := &net.Dialer{
		Timeout:   time.Second,
		LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(bindAddr, 0)),
	}
	connection, err = dialer.DialContext(ctx, "tcp", destinationAddrPort.String())
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("binding TCP port: %w", err)
	}

	tcpAddr := connection.LocalAddr().(*net.TCPAddr) //nolint:forcetypeassert
	sourceAddr = tcpAddr.AddrPort()

	return connection, sourceAddr, nil
}
