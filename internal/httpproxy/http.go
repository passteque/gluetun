package httpproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func (h *handler) handleHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.URL.Scheme {
	case "http", "https":
	default:
		h.logger.Warn("Unsupported scheme " + request.URL.Scheme)
		http.Error(responseWriter, "unsupported scheme", http.StatusBadRequest)
		return
	}

	request = request.WithContext(h.ctx)

	request.RequestURI = ""

	for _, key := range hopHeaders {
		request.Header.Del(key)
	}

	if !h.stealth {
		setForwardedHeaders(request)
	}

	response, err := h.client.Do(request) //nolint:gosec // SSRF is the feature: HTTP proxy forwards to arbitrary URLs
	if err != nil {
		http.Error(responseWriter, "server error", http.StatusInternalServerError)
		h.logger.Warn("cannot process request for client " + request.RemoteAddr + ": " + err.Error())
		return
	}
	defer response.Body.Close()
	if h.verbose {
		h.logger.Info(request.RemoteAddr + " " + response.Status + " " +
			request.Method + " " + request.URL.String())
	}

	for _, key := range hopHeaders {
		response.Header.Del(key)
	}

	targetHeaderPtr := responseWriter.Header()
	for key, values := range response.Header {
		for _, value := range values {
			targetHeaderPtr.Add(key, value)
		}
	}

	responseWriter.WriteHeader(response.StatusCode)
	if _, err := io.Copy(responseWriter, response.Body); err != nil {
		h.logger.Error(request.RemoteAddr + " " + request.URL.String() +
			": body copy error: " + err.Error())
	}
}

func setForwardedHeaders(request *http.Request) {
	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return
	}
	// keep existing proxy headers
	if prior, ok := request.Header["X-Forwarded-For"]; ok {
		clientIP = fmt.Sprintf("%s,%s", strings.Join(prior, ", "), clientIP)
	}
	request.Header.Set("X-Forwarded-For", clientIP)
}
