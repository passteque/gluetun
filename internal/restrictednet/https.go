package restrictednet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/qdm12/gluetun/internal/pmtud/constants"
)

// OpenHTTPS opens temporary restrictive firewall output for one HTTPS destination.
// The returned cleanup function must be called to remove the temporary firewall rule and close connections.
func (c *Client) OpenHTTPS(ctx context.Context, destinationTLSName string, destinationIP netip.Addr,
) (httpClient *http.Client, cleanup func() error, err error) {
	fd, sourceAddrPort, err := bindSourceConnection(destinationIP)
	if err != nil {
		return nil, nil, fmt.Errorf("binding source port: %w", err)
	}

	destinationAddrPort := netip.AddrPortFrom(destinationIP, c.httpsPort)

	const remove = false
	err = c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
		sourceAddrPort, destinationAddrPort, remove)
	if err != nil {
		closeFD(fd)
		return nil, nil, fmt.Errorf("allowing output traffic through firewall: %w", err)
	}

	connection, err := connectSourceConnection(ctx, fd, destinationAddrPort)
	if err != nil {
		const remove = true
		_ = c.firewall.AcceptOutputFromIPPortToIPPort(ctx, "tcp", c.outboundInterface,
			sourceAddrPort, destinationAddrPort, remove)
		return nil, nil, fmt.Errorf("connecting source socket: %w", err)
	}

	httpClient = newHTTPSClient(destinationTLSName, connection)
	cleanup = func() error {
		var errs []error
		httpClient.CloseIdleConnections()
		const remove = true
		err := c.firewall.AcceptOutputFromIPPortToIPPort(context.Background(), "tcp", c.outboundInterface,
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

func newHTTPSClient(destinationTLSName string, connection net.Conn) *http.Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert
	httpTransport.Proxy = nil
	httpTransport.MaxIdleConns = 1
	httpTransport.MaxIdleConnsPerHost = 1
	httpTransport.MaxConnsPerHost = 1
	httpTransport.IdleConnTimeout = time.Second
	httpTransport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: destinationTLSName,
	}

	_, destinationPort, _ := net.SplitHostPort(connection.RemoteAddr().String())
	expectedAddress := net.JoinHostPort(destinationTLSName, destinationPort)
	httpTransport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("unexpected dial network %q", network)
		}
		if address != expectedAddress {
			return nil, fmt.Errorf("unexpected dial address %q (expected %q)", address, expectedAddress)
		}
		return connection, nil
	}

	const timeout = 5 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}
}

func bindSourceConnection(destinationIP netip.Addr) (fd int, sourceAddr netip.AddrPort, err error) {
	sourceIP, err := sourceIPForDestination(destinationIP)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("finding source IP: %w", err)
	}

	family := constants.AF_INET
	if sourceIP.Is6() {
		family = constants.AF_INET6
	}

	fd, err = newTCPSockStream(family)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("creating socket: %w", err)
	}

	bindAddrPort := netip.AddrPortFrom(sourceIP, 0)
	err = bindFD(fd, bindAddrPort)
	if err != nil {
		closeFD(fd)
		return 0, netip.AddrPort{}, fmt.Errorf("binding socket: %w", err)
	}

	sourceAddr, err = fdToSourceAddr(fd)
	if err != nil {
		closeFD(fd)
		return 0, netip.AddrPort{}, fmt.Errorf("getting source address: %w", err)
	}

	return fd, sourceAddr, nil
}

func connectSourceConnection(ctx context.Context, fd int, destinationAddrPort netip.AddrPort) (
	connection net.Conn, err error,
) {
	errCh := make(chan error)
	go func() {
		errCh <- connectFD(fd, destinationAddrPort)
	}()

	select {
	case err = <-errCh:
		if err != nil {
			closeFD(fd)
			return nil, fmt.Errorf("connecting socket: %w", err)
		}
	case <-ctx.Done():
		err = ctx.Err()
		closeFD(fd)
		connectErr := <-errCh
		if connectErr != nil {
			err = fmt.Errorf("%w (%w)", connectErr, err)
		}
		return nil, fmt.Errorf("connecting socket: %w", err)
	}

	file := os.NewFile(uintptr(fd), "")
	if file == nil {
		closeFD(fd)
		return nil, fmt.Errorf("creating socket file")
	}
	defer file.Close()

	connection, err = net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("wrapping socket connection: %w", err)
	}

	return connection, nil
}

func sourceIPForDestination(destinationIP netip.Addr) (srcIP netip.Addr, err error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()

	family := uint8(constants.AF_INET)
	if destinationIP.Is6() {
		family = constants.AF_INET6
	}

	requestMessage := &rtnetlink.RouteMessage{
		Family: family,
		Attributes: rtnetlink.RouteAttributes{
			Dst: destinationIP.AsSlice(),
		},
	}
	messages, err := conn.Route.Get(requestMessage)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("getting routes to %s: %w", destinationIP, err)
	}

	for _, message := range messages {
		if message.Attributes.Src == nil {
			continue
		}
		if message.Attributes.Src.To4() == nil {
			return netip.AddrFrom16([16]byte(message.Attributes.Src)), nil
		}
		return netip.AddrFrom4([4]byte(message.Attributes.Src)), nil
	}

	return netip.Addr{}, fmt.Errorf("no route to %s", destinationIP)
}
