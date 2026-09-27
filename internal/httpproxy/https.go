package httpproxy

import (
	"io"
	"net"
	"net/http"
)

func (h *handler) handleHTTPS(responseWriter http.ResponseWriter, request *http.Request) {
	dialer := net.Dialer{}
	destinationConn, err := dialer.DialContext(h.ctx, "tcp", request.Host)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusServiceUnavailable)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)

	hijacker, ok := responseWriter.(http.Hijacker)
	if !ok {
		http.Error(responseWriter, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConnection, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		h.logger.Warn(err.Error())
		http.Error(responseWriter, err.Error(), http.StatusServiceUnavailable)
		if err := destinationConn.Close(); err != nil {
			h.logger.Error("closing destination connection: " + err.Error())
		}
		return
	}

	if h.verbose {
		h.logger.Info(request.RemoteAddr + " <-> " + request.Host)
	}

	h.wg.Add(1)

	serverToClientDone := make(chan struct{})
	clientToServerClientDone := make(chan struct{})
	// Read the client side through the buffer Hijack() returned, not the bare connection:
	// net/http's background read may already have consumed the first bytes the client sent.
	go transfer(destinationConn, bufferedClientConn{
		Reader: clientBuffer.Reader,
		Closer: clientConnection,
	}, clientToServerClientDone)
	go transfer(clientConnection, destinationConn, serverToClientDone)

	select {
	case <-h.ctx.Done():
		destinationConn.Close()
		clientConnection.Close()
		<-serverToClientDone
		<-clientToServerClientDone
	case <-serverToClientDone:
		<-clientToServerClientDone
	case <-clientToServerClientDone: // happens more rarely, when a connection is closed on the client side
		<-serverToClientDone
	}

	h.wg.Done()
}

// bufferedClientConn reads from the buffered reader net/http hands back from Hijack(), while
// closing the underlying connection. A *bufio.Reader is not an io.ReadCloser, so the two halves
// are combined here.
//
// This exists because net/http keeps a background read running on the connection while a
// body-less handler (such as CONNECT) executes, and Hijack() flushes the already-written 200
// response to the client before it cancels that read. A client that sends immediately — a TLS
// ClientHello a millisecond or two later, on a fast local network — can land inside that window,
// in which case the background read consumes its first byte and returns it inside the
// *bufio.ReadWriter. Forwarding the raw connection instead of that buffer silently drops the
// byte, and the destination server receives a stream that is off by one: a TLS ClientHello
// missing its 0x16 record-type prefix, which the peer rejects as not-TLS.
type bufferedClientConn struct {
	io.Reader
	io.Closer
}

func transfer(destination io.WriteCloser, source io.ReadCloser, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	_ = source.Close()
	_ = destination.Close()
	close(done)
}
