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

	hijacker, ok := responseWriter.(http.Hijacker)
	if !ok {
		http.Error(responseWriter, "Hijacking not supported", http.StatusInternalServerError)
		if err := destinationConn.Close(); err != nil {
			h.logger.Error("closing destination connection: " + err.Error())
		}
		return
	}
	clientConnection, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Warn(err.Error())
		if err := destinationConn.Close(); err != nil {
			h.logger.Error("closing destination connection: " + err.Error())
		}
		return
	}

	// Write the CONNECT response manually after hijacking to avoid
	// Go's net/http adding Transfer-Encoding: chunked, which violates
	// RFC 7231 Section 4.3.6 and breaks clients like FFmpeg.
	_, err = clientConnection.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		h.logger.Warn("writing CONNECT response: " + err.Error())
		_ = clientConnection.Close()
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
	go transfer(destinationConn, clientConnection, clientToServerClientDone)
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

func transfer(destination io.WriteCloser, source io.ReadCloser, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	_ = source.Close()
	_ = destination.Close()
	close(done)
}
