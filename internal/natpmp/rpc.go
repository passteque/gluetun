package natpmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func (c *Client) rpc(ctx context.Context, gateway netip.Addr,
	request []byte, responseSize uint) (
	response []byte, err error,
) {
	if gateway.IsUnspecified() || !gateway.IsValid() {
		return nil, errors.New("gateway IP is unspecified")
	}

	err = checkRequest(request)
	if err != nil {
		return nil, fmt.Errorf("checking request: %w", err)
	}

	gatewayAddress := &net.UDPAddr{
		IP:   gateway.AsSlice(),
		Port: int(c.serverPort),
	}

	connection, err := net.DialUDP("udp", nil, gatewayAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing udp: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	endGoroutineDone := make(chan struct{})
	defer func() {
		cancel()
		<-endGoroutineDone
	}()
	ctxListeningReady := make(chan struct{})
	go func() {
		defer close(endGoroutineDone)
		close(ctxListeningReady)
		// Context is canceled either by the parent context or
		// when this function returns.
		<-ctx.Done()
		closeErr := connection.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("closing connection: %w", closeErr)
			return
		}
		err = fmt.Errorf("%w; closing connection: %w", err, closeErr)
	}()
	<-ctxListeningReady // really to make unit testing reliable

	const maxResponseSize = 16
	response = make([]byte, maxResponseSize)

	// Connection duration doubles on every network error
	// Note it does not double if the source IP mismatches the gateway IP.
	connectionDuration := c.initialConnectionDuration

	var retryCount uint
	var failedAttempts []string
	for retryCount = 0; retryCount < c.maxRetries; retryCount++ { //nolint:intrange
		deadline := time.Now().Add(connectionDuration)
		err = connection.SetDeadline(deadline)
		if err != nil {
			return nil, fmt.Errorf("setting connection deadline: %w", err)
		}

		_, err = connection.Write(request)
		if err != nil {
			return nil, fmt.Errorf("writing to connection: %w", err)
		}

		bytesRead, receivedRemoteAddress, err := connection.ReadFromUDP(response)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("reading from udp connection: %w", ctx.Err())
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				connectionDuration *= 2
				failedAttempts = append(failedAttempts, netErr.Error())
				continue
			}
			return nil, fmt.Errorf("reading from udp connection: %w", err)
		}

		if !receivedRemoteAddress.IP.Equal(gatewayAddress.IP) {
			// Upon receiving a response packet, the client MUST check the source IP
			// address, and silently discard the packet if the address is not the
			// address of the gateway to which the request was sent.
			failedAttempts = append(failedAttempts,
				fmt.Sprintf("received response from %s instead of gateway IP %s",
					receivedRemoteAddress.IP, gatewayAddress.IP))
			continue
		}

		response = response[:bytesRead]
		break
	}

	if retryCount == c.maxRetries {
		return nil, fmt.Errorf("connection timeout: failed attempts: %s", dedupFailedAttempts(failedAttempts))
	}

	// Opcodes between 0 and 127 are client requests.  Opcodes from 128 to
	// 255 are corresponding server responses.
	const operationCodeMask = 128
	expectedOperationCode := request[1] | operationCodeMask
	err = checkResponse(response, expectedOperationCode, responseSize)
	if err != nil {
		return nil, fmt.Errorf("checking response: %w", err)
	}

	return response, nil
}

func dedupFailedAttempts(failedAttempts []string) (errorMessage string) {
	type data struct {
		message string
		indices []int
	}
	messageToData := make(map[string]data, len(failedAttempts))
	for i, message := range failedAttempts {
		metadata, ok := messageToData[message]
		if !ok {
			metadata.message = message
		}
		metadata.indices = append(metadata.indices, i)
		sort.Slice(metadata.indices, func(i, j int) bool {
			return metadata.indices[i] < metadata.indices[j]
		})
		messageToData[message] = metadata
	}

	// Sort by first index
	dataSlice := make([]data, 0, len(messageToData))
	for _, metadata := range messageToData {
		dataSlice = append(dataSlice, metadata)
	}
	sort.Slice(dataSlice, func(i, j int) bool {
		return dataSlice[i].indices[0] < dataSlice[j].indices[0]
	})

	dedupedFailedAttempts := make([]string, 0, len(dataSlice))
	for _, data := range dataSlice {
		newMessage := fmt.Sprintf("%s (%s)", data.message,
			indicesToTryString(data.indices))
		dedupedFailedAttempts = append(dedupedFailedAttempts, newMessage)
	}
	return strings.Join(dedupedFailedAttempts, "; ")
}

func indicesToTryString(indices []int) string {
	if len(indices) == 1 {
		return fmt.Sprintf("try %d", indices[0]+1)
	}
	tries := make([]string, len(indices))
	for i, index := range indices {
		tries[i] = fmt.Sprintf("%d", index+1)
	}
	return fmt.Sprintf("tries %s", strings.Join(tries, ", "))
}
