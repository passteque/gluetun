package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

type udpAssociation struct {
	id              uint64
	clientAddrPort  netip.AddrPort
	controlConnAddr netip.Addr
	packetCh        chan *bytes.Buffer
}

type udpRouter struct {
	logger Logger

	listener                      net.PacketConn
	mutex                         sync.Mutex
	bufferPool                    sync.Pool
	nextAssociationID             uint64
	clientAddrPortToAssociation   map[netip.AddrPort]udpAssociation
	clientIPToPendingAssociations map[netip.Addr][]udpAssociation
	associationIDToClientAddrPort map[uint64]netip.AddrPort
}

const (
	maxUDPPacketLength            = 65535
	maxSOCKS5UDPDatagramOverhead  = 3 + 1 + 16 + 2
	pooledUDPPacketBufferCapacity = maxUDPPacketLength + maxSOCKS5UDPDatagramOverhead
)

func newUDPRouter(ctx context.Context, address string, logger Logger) (router *udpRouter, err error) {
	config := &net.ListenConfig{}
	listener, err := config.ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("UDP listening: %w", err)
	}

	return &udpRouter{
		logger:   logger,
		listener: listener,
		bufferPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, pooledUDPPacketBufferCapacity))
			},
		},
		nextAssociationID:             1,
		clientAddrPortToAssociation:   make(map[netip.AddrPort]udpAssociation),
		clientIPToPendingAssociations: make(map[netip.Addr][]udpAssociation),
		associationIDToClientAddrPort: make(map[uint64]netip.AddrPort),
	}, nil
}

func (r *udpRouter) localAddress() net.Addr {
	return r.listener.LocalAddr()
}

func (r *udpRouter) close() error {
	return r.listener.Close()
}

func (r *udpRouter) registerAssociation(controlConn net.Conn) (udpAssociation, error) {
	controlConnAddrPort, err := netip.ParseAddrPort(controlConn.RemoteAddr().String())
	if err != nil {
		return udpAssociation{}, fmt.Errorf("parsing control connection address: %w", err)
	}
	controlConnAddr := controlConnAddrPort.Addr().Unmap()

	r.mutex.Lock()
	defer r.mutex.Unlock()

	const udpPacketChannelBuffer = 2
	associationID := r.nextAssociationID
	r.nextAssociationID++

	association := udpAssociation{
		id:              associationID,
		controlConnAddr: controlConnAddr,
		packetCh:        make(chan *bytes.Buffer, udpPacketChannelBuffer),
	}

	pendingAssociations := r.clientIPToPendingAssociations[controlConnAddr]
	pendingAssociations = append(pendingAssociations, association)
	r.clientIPToPendingAssociations[controlConnAddr] = pendingAssociations

	return association, nil
}

func (r *udpRouter) unregisterAssociation(association udpAssociation) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	clientAddrPort, hasClientAddress := r.associationIDToClientAddrPort[association.id]
	if hasClientAddress {
		delete(r.associationIDToClientAddrPort, association.id)
		delete(r.clientAddrPortToAssociation, clientAddrPort)
	}

	if association.clientAddrPort.IsValid() {
		delete(r.clientAddrPortToAssociation, association.clientAddrPort)
	}

	pendingAssociations := r.clientIPToPendingAssociations[association.controlConnAddr]
	for i, pendingAssociation := range pendingAssociations {
		if pendingAssociation.id == association.id {
			pendingAssociations = append(pendingAssociations[:i], pendingAssociations[i+1:]...)
			break
		}
	}
	if len(pendingAssociations) == 0 {
		delete(r.clientIPToPendingAssociations, association.controlConnAddr)
	} else {
		r.clientIPToPendingAssociations[association.controlConnAddr] = pendingAssociations
	}
}

func (r *udpRouter) run(ctx context.Context) error {
	packetBuffer := make([]byte, maxUDPPacketLength)

	for {
		packetLength, sourceAddress, err := r.listener.ReadFrom(packetBuffer)
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading UDP packet: %w", err)
		}

		sourceAddrPort, err := netAddrToNetipAddrPort(sourceAddress)
		if err != nil {
			r.logger.Warnf("parsing source address: %s", err)
			continue
		}
		buffer := r.bufferPool.Get().(*bytes.Buffer) //nolint:forcetypeassert
		buffer.Reset()
		_, err = buffer.Write(packetBuffer[:packetLength])
		if err != nil {
			r.bufferPool.Put(buffer)
			r.logger.Warnf("buffering packet: %s", err)
			continue
		}
		err = r.routePacket(sourceAddrPort, buffer)
		if err != nil {
			r.logger.Warnf("failed routing UDP packet: %s", err)
		}
	}
}

func (r *udpRouter) routePacket(sourceAddrPort netip.AddrPort, packet *bytes.Buffer) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	association, packetFromClient := r.findClientAssociation(sourceAddrPort)
	if !packetFromClient {
		r.bufferPool.Put(packet)
		return nil
	}

	select {
	case association.packetCh <- packet:
		return nil
	default:
		r.bufferPool.Put(packet)
		return errors.New("association packet queue full")
	}
}

func (r *udpRouter) findClientAssociation(sourceAddrPort netip.AddrPort) (
	association udpAssociation, ok bool,
) {
	association, ok = r.clientAddrPortToAssociation[sourceAddrPort]
	if ok {
		return association, true
	}
	sourceAddr := sourceAddrPort.Addr()

	pendingAssociations := r.clientIPToPendingAssociations[sourceAddr]
	if len(pendingAssociations) == 0 {
		return udpAssociation{}, false
	}

	association = pendingAssociations[0]
	r.clientIPToPendingAssociations[sourceAddr] = pendingAssociations[1:]
	if len(r.clientIPToPendingAssociations[sourceAddr]) == 0 {
		delete(r.clientIPToPendingAssociations, sourceAddr)
	}

	association.clientAddrPort = sourceAddrPort
	r.clientAddrPortToAssociation[sourceAddrPort] = association
	r.associationIDToClientAddrPort[association.id] = sourceAddrPort

	return association, true
}

func (r *udpRouter) clientAddrPortForAssociation(associationID uint64) (
	clientAddrPort netip.AddrPort, ok bool,
) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	clientAddrPort, ok = r.associationIDToClientAddrPort[associationID]
	return clientAddrPort, ok
}

func (r *udpRouter) runAssociationHandler(ctx context.Context, association udpAssociation) {
	config := &net.ListenConfig{}
	socket, err := config.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		r.logger.Warnf("creating per-association UDP socket: %s", err)
		return
	}
	defer socket.Close()

	go closeSocketOnContextDone(ctx, socket)

	packetBuffer := make([]byte, maxUDPPacketLength)

	forwardDoneCh := make(chan struct{})
	go r.forwardClientPackets(ctx, socket, association.packetCh, forwardDoneCh)

	for {
		packetLength, sourceAddress, err := socket.ReadFrom(packetBuffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				<-forwardDoneCh
				return
			}
			r.logger.Warnf("reading from per-association UDP socket: %s", err)
			continue
		}

		sourceAddrPort, err := netAddrToNetipAddrPort(sourceAddress)
		if err != nil {
			r.logger.Warnf("parsing source address from destination: %s", err)
			continue
		}

		buffer := r.bufferPool.Get().(*bytes.Buffer) //nolint:forcetypeassert
		buffer.Reset()
		err = encodeUDPDatagramToBuffer(buffer, sourceAddrPort, packetBuffer[:packetLength])
		if err != nil {
			r.bufferPool.Put(buffer)
			r.logger.Warnf("encoding response datagram: %s", err)
			continue
		}

		clientAddrPort, found := r.clientAddrPortForAssociation(association.id)
		if !found {
			r.bufferPool.Put(buffer)
			r.logger.Warnf("client address not found for association id %d", association.id)
			continue
		}

		clientUDPAddress := &net.UDPAddr{
			IP:   clientAddrPort.Addr().AsSlice(),
			Port: int(clientAddrPort.Port()),
		}
		_, err = r.listener.WriteTo(buffer.Bytes(), clientUDPAddress)
		r.bufferPool.Put(buffer)
		if err != nil {
			r.logger.Warnf("writing response to client: %s", err)
		}
	}
}

func closeSocketOnContextDone(ctx context.Context, socket net.PacketConn) {
	<-ctx.Done()
	_ = socket.Close()
}

func (r *udpRouter) forwardClientPackets(ctx context.Context, socket net.PacketConn,
	packetCh <-chan *bytes.Buffer, done chan<- struct{},
) {
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return
		case buffer, ok := <-packetCh:
			if !ok {
				return
			}

			err := r.writeClientPacketToDestination(ctx, socket, buffer)
			r.bufferPool.Put(buffer)
			if err != nil {
				r.logger.Warnf("forwarding client packet to destination: %s", err)
			}
		}
	}
}

func (r *udpRouter) writeClientPacketToDestination(ctx context.Context,
	socket net.PacketConn, packet *bytes.Buffer,
) error {
	destination, payload, err := decodeUDPDatagram(packet.Bytes())
	if err != nil {
		return fmt.Errorf("decoding UDP datagram: %w", err)
	}

	resolvedDestinationUDPAddress, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		return fmt.Errorf("resolving destination UDP address: %w", err)
	}

	_, err = socket.WriteTo(payload, resolvedDestinationUDPAddress)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("writing payload to destination: %w", err)
	}

	return nil
}

func netAddrToNetipAddrPort(addr net.Addr) (netip.AddrPort, error) {
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parsing address: %w", err)
	}
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}
