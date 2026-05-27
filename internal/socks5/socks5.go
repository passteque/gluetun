package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var (
	errNoMethodIdentifiers     = errors.New("no method identifiers")
	errNoValidMethodIdentifier = errors.New("no valid method identifier")
)

type socksConn struct {
	// Injected fields
	dialer     *net.Dialer
	username   string
	password   string
	clientConn net.Conn
	udpRouter  *udpRouter
	logger     Logger
}

func (c *socksConn) closeClientConn(ctxErr error) {
	err := c.clientConn.Close()
	if err != nil && ctxErr == nil {
		c.logger.Warnf("closing client connection: %s", err)
	}
}

func (c *socksConn) run(ctx context.Context) error {
	// Monitoring context cancellation to close the connection and stop
	// reading operations on clientConn.
	done := make(chan struct{})
	ctxWatcherDone := make(chan struct{})
	go func() {
		defer close(ctxWatcherDone)
		select {
		case <-done:
		case <-ctx.Done():
			// unblock read operations
			c.closeClientConn(ctx.Err())
		}
	}()
	defer func() {
		close(done)
		<-ctxWatcherDone
	}()

	authMethod := authNotRequired
	if c.username != "" || c.password != "" {
		authMethod = authUsernamePassword
	}

	err := verifyFirstNegotiation(c.clientConn, authMethod)
	if err != nil {
		replyMethod := authMethod
		if errors.Is(err, errNoMethodIdentifiers) || errors.Is(err, errNoValidMethodIdentifier) {
			replyMethod = authNotAcceptable
		}
		_, writeErr := c.clientConn.Write([]byte{socks5Version, byte(replyMethod)})
		if writeErr != nil {
			c.logger.Warnf("failed writing first negotiation reply: %s", writeErr)
		}
		c.closeClientConn(ctx.Err())
		return fmt.Errorf("verifying first negotiation: %w", err)
	}

	_, err = c.clientConn.Write([]byte{socks5Version, byte(authMethod)})
	if err != nil {
		c.closeClientConn(ctx.Err())
		return fmt.Errorf("writing first negotiation reply: %w", err)
	}

	switch authMethod {
	case authNotRequired, authNotAcceptable:
	case authGssapi:
		panic("not implemented")
	case authUsernamePassword:
		// See https://datatracker.ietf.org/doc/html/rfc1929#section-2
		err = usernamePasswordSubnegotiate(c.clientConn, c.username, c.password)
		if err != nil {
			// If the server returns a `failure' (STATUS value other than X'00') status,
			// it MUST close the connection.
			c.closeClientConn(ctx.Err())
			return fmt.Errorf("subnegotiating username and password: %w", err)
		}
	default:
		panic(fmt.Sprintf("unimplemented auth method %d", authMethod))
	}

	err = c.handleRequest(ctx)
	c.closeClientConn(ctx.Err())
	if err != nil {
		return fmt.Errorf("handling request: %w", err)
	}
	return nil
}

func (c *socksConn) handleRequest(ctx context.Context) error {
	const socksVersion = socks5Version
	request, err := decodeRequest(c.clientConn, socksVersion)
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return err
	}

	switch request.command {
	case connect:
		err = c.handleConnectRequest(ctx, socksVersion, request)
		if err != nil {
			return fmt.Errorf("handling %s request: %w", request.command, err)
		}
		return nil
	case udpAssociate:
		err = c.handleUDPAssociateRequest(ctx, socksVersion)
		if err != nil {
			return fmt.Errorf("handling %s request: %w", request.command, err)
		}
		return nil
	default:
		c.encodeFailedResponse(c.clientConn, socksVersion, commandNotSupported)
		return fmt.Errorf("command %s is not supported", request.command)
	}
}

func (c *socksConn) handleConnectRequest(ctx context.Context,
	socksVersion byte, request request,
) error {
	destinationAddress := net.JoinHostPort(request.destination, fmt.Sprint(request.port))
	destinationConn, err := c.dialer.DialContext(ctx, "tcp", destinationAddress)
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return err
	}
	defer destinationConn.Close()

	destinationServerAddress := destinationConn.LocalAddr().String()
	destinationAddr, destinationPortStr, err := net.SplitHostPort(destinationServerAddress)
	if err != nil {
		return fmt.Errorf("splitting destination address: %w", err)
	}
	destinationPort, err := strconv.ParseUint(destinationPortStr, 10, 16)
	if err != nil {
		return fmt.Errorf("port is malformed: %q", destinationPortStr)
	}

	var bindAddrType addrType
	if ip := net.ParseIP(destinationAddr); ip != nil {
		if ip.To4() != nil {
			bindAddrType = ipv4
		} else {
			bindAddrType = ipv6
		}
	} else {
		bindAddrType = domainName
	}

	err = c.encodeSuccessResponse(c.clientConn, socksVersion, succeeded, bindAddrType,
		destinationAddr, uint16(destinationPort))
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return fmt.Errorf("writing successful %s response: %w", request.command, err)
	}

	const capacity = 2 // if one goroutine fails, we don't want to leak the other one
	errc := make(chan error, capacity)
	go func() {
		_, err := io.Copy(c.clientConn, destinationConn)
		if err != nil {
			err = fmt.Errorf("from backend to client: %w", err)
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(destinationConn, c.clientConn)
		if err != nil {
			err = fmt.Errorf("from client to backend: %w", err)
		}
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		_ = destinationConn.Close()
		_ = c.clientConn.Close()
		return nil
	}
}

func (c *socksConn) handleUDPAssociateRequest(ctx context.Context,
	socksVersion byte,
) error {
	bindAddress, bindPort, bindAddrType, err := c.udpAssociationAddresses()
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return fmt.Errorf("getting udp association addresses: %w", err)
	}

	err = c.encodeSuccessResponse(c.clientConn, socksVersion, succeeded,
		bindAddrType, bindAddress, bindPort)
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return fmt.Errorf("writing successful %s response: %w", udpAssociate, err)
	}

	association, err := c.udpRouter.registerAssociation(c.clientConn)
	if err != nil {
		c.encodeFailedResponse(c.clientConn, socksVersion, generalServerFailure)
		return fmt.Errorf("registering udp association: %w", err)
	}
	defer c.udpRouter.unregisterAssociation(association)

	associationCtx, associationCancel := context.WithCancel(ctx)
	defer associationCancel()

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		c.udpRouter.runAssociationHandler(associationCtx, association)
	}()

	go func() {
		_, _ = io.Copy(io.Discard, c.clientConn)
		associationCancel()
	}()
	<-associationCtx.Done()
	<-handlerDone
	return nil
}

func (c *socksConn) udpAssociationAddresses() (bindAddress string,
	bindPort uint16, bindAddrType addrType, err error,
) {
	localAddress := c.udpRouter.localAddress().String()
	host, portString, err := net.SplitHostPort(localAddress)
	if err != nil {
		return "", 0, 0, fmt.Errorf("splitting local address: %w", err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return "", 0, 0, fmt.Errorf("parsing local port: %w", err)
	}
	bindAddress = host
	bindPort = uint16(port)

	ipAddress := net.ParseIP(bindAddress)
	if ipAddress == nil {
		bindAddrType = domainName
		return bindAddress, bindPort, bindAddrType, nil
	}

	if ipAddress.To4() != nil {
		bindAddrType = ipv4
	} else {
		bindAddrType = ipv6
	}

	return bindAddress, bindPort, bindAddrType, nil
}

func decodeUDPDatagram(packet []byte) (destination string, payload []byte, err error) {
	const minimumPacketLength = 4
	if len(packet) < minimumPacketLength {
		return "", nil, fmt.Errorf("packet is too short: %d", len(packet))
	}
	if packet[0] != 0 || packet[1] != 0 {
		return "", nil, fmt.Errorf("reserved bytes are invalid: %x %x", packet[0], packet[1])
	}
	if packet[2] != 0 {
		return "", nil, fmt.Errorf("fragmentation is not supported")
	}

	offset := 3
	addressType := addrType(packet[offset])
	offset++

	switch addressType {
	case ipv4:
		const ipv4Length = 4
		if len(packet) < offset+ipv4Length+2 {
			return "", nil, fmt.Errorf("packet is too short for IPv4 address")
		}
		var ip [ipv4Length]byte
		copy(ip[:], packet[offset:offset+ipv4Length])
		destination = netip.AddrFrom4(ip).String()
		offset += ipv4Length
	case ipv6:
		const ipv6Length = 16
		if len(packet) < offset+ipv6Length+2 {
			return "", nil, fmt.Errorf("packet is too short for IPv6 address")
		}
		var ip [ipv6Length]byte
		copy(ip[:], packet[offset:offset+ipv6Length])
		destination = netip.AddrFrom16(ip).String()
		offset += ipv6Length
	case domainName:
		if len(packet) < offset+1 {
			return "", nil, fmt.Errorf("packet is too short for domain name length")
		}
		domainNameLength := int(packet[offset])
		offset++
		if len(packet) < offset+domainNameLength+2 {
			return "", nil, fmt.Errorf("packet is too short for domain name")
		}
		destination = string(packet[offset : offset+domainNameLength])
		offset += domainNameLength
	default:
		return "", nil, fmt.Errorf("address type is not supported: %d", addressType)
	}

	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	destination = net.JoinHostPort(destination, fmt.Sprint(port))
	offset += 2
	payload = packet[offset:]

	return destination, payload, nil
}

func encodeUDPDatagramToBuffer(writer io.Writer, sourceAddrPort netip.AddrPort,
	payload []byte,
) error {
	address := sourceAddrPort.Addr()
	if !address.IsValid() {
		return errors.New("source address is not valid")
	}

	err := writeUDPDatagramSourceAddress(writer, address)
	if err != nil {
		return fmt.Errorf("writing source address: %w", err)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], sourceAddrPort.Port())
	_, err = writer.Write(portBytes[:])
	if err != nil {
		return fmt.Errorf("writing destination port: %w", err)
	}

	_, err = writer.Write(payload)
	if err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	return nil
}

func writeUDPDatagramSourceAddress(writer io.Writer, address netip.Addr) error {
	var addrType addrType
	var addressBytes []byte
	switch {
	case address.Is4():
		addrType = ipv4
		array := address.As4()
		addressBytes = array[:]
	case address.Is6():
		addrType = ipv6
		array := address.As16()
		addressBytes = array[:]
	}

	_, err := writer.Write([]byte{0, 0, 0, byte(addrType)})
	if err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	_, err = writer.Write(addressBytes)
	if err != nil {
		return fmt.Errorf("writing IP address: %w", err)
	}
	return nil
}

// See https://datatracker.ietf.org/doc/html/rfc1928#section-3
func verifyFirstNegotiation(reader io.Reader, requiredMethod authMethod) error {
	const headerLength = 2 // version + nMethods bytes
	header := make([]byte, headerLength)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("version is not supported: %d", header[0])
	}

	nMethods := header[1]
	if nMethods == 0 {
		return fmt.Errorf("%w", errNoMethodIdentifiers)
	}

	methodIdentifiers := make([]byte, nMethods)
	_, err = io.ReadFull(reader, methodIdentifiers)
	if err != nil {
		return fmt.Errorf("reading method identifiers: %w", err)
	}
	for _, methodIdentifier := range methodIdentifiers {
		if methodIdentifier == byte(requiredMethod) {
			return nil
		}
	}

	return makeNoAcceptableMethodError(requiredMethod, methodIdentifiers)
}

func makeNoAcceptableMethodError(requiredAuthMethod authMethod, methodIdentifiers []byte) error {
	methodNames := make([]string, len(methodIdentifiers))
	for i, methodIdentifier := range methodIdentifiers {
		methodNames[i] = fmt.Sprintf("%q", authMethod(methodIdentifier))
	}

	return fmt.Errorf("%w: none of %s matches %s",
		errNoValidMethodIdentifier, strings.Join(methodNames, ", "),
		requiredAuthMethod)
}

// See https://datatracker.ietf.org/doc/html/rfc1928#section-4
type request struct {
	command     cmdType
	destination string
	port        uint16
	addressType addrType
}

func decodeRequest(reader io.Reader, expectedVersion byte) (req request, err error) {
	const headerLength = 4
	header := [headerLength]byte{}
	_, err = io.ReadFull(reader, header[:])
	if err != nil {
		return request{}, fmt.Errorf("reading header: %w", err)
	}

	version := header[0]
	switch {
	case version != expectedVersion:
		return request{}, fmt.Errorf("version is not supported: expected %d and got %d",
			expectedVersion, version)
	case header[2] != 0:
		return request{}, fmt.Errorf("reserved header byte must be 0 but got %d", header[2])
	}

	req.command = cmdType(header[1])
	// header[2] is RSV byte
	req.addressType = addrType(header[3])

	switch req.addressType {
	case ipv4:
		var ip [4]byte
		_, err = io.ReadFull(reader, ip[:])
		if err != nil {
			return request{}, fmt.Errorf("reading IPv4 address: %w", err)
		}
		req.destination = netip.AddrFrom4(ip).String()
	case ipv6:
		var ip [16]byte
		_, err = io.ReadFull(reader, ip[:])
		if err != nil {
			return request{}, fmt.Errorf("reading IPv6 address: %w", err)
		}
		req.destination = netip.AddrFrom16(ip).String()
	case domainName:
		var header [1]byte
		_, err = io.ReadFull(reader, header[:])
		if err != nil {
			return request{}, fmt.Errorf("reading domain name header: %w", err)
		}
		domainName := make([]byte, header[0])
		_, err = io.ReadFull(reader, domainName)
		if err != nil {
			return request{}, fmt.Errorf("reading domain name bytes: %w", err)
		}
		req.destination = string(domainName)
	default:
		return request{}, fmt.Errorf("address type is not supported: %d", req.addressType)
	}

	var portBytes [2]byte
	_, err = io.ReadFull(reader, portBytes[:])
	if err != nil {
		return request{}, fmt.Errorf("reading port: %w", err)
	}
	req.port = binary.BigEndian.Uint16(portBytes[:])

	return req, nil
}
