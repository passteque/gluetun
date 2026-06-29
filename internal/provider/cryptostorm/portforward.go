package cryptostorm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
)

// portRangePattern matches the valid Cryptostorm port range 30000-65535.
const portRangePattern = `([3-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])`

// ipPattern matches either an IPv4 address or a bracketed IPv6 address.
const ipPattern = `(?:\d+\.\d+\.\d+\.\d+|\[[0-9a-fA-F:]+\])`

// regexForwardPlainText matches plain text responses (e.g. from curl):
//
//	37.120.234.253:55555 -> 10.10.123.139:55555
//	[2400:a842:c46e:1::4a]:55555 -> [fd00:10:10::e0e0]:55555
var regexForwardPlainText = regexp.MustCompile(
	ipPattern + `:` + portRangePattern + `\s*->\s*` + ipPattern + `:\d+`)

// regexForwardHTML matches the HTML response from the port forwarding page.
// Each forwarded port has a hidden delete input:
//
//	<input type="hidden" name="delfwd" value="30000">
var regexForwardHTML = regexp.MustCompile(
	`name="delfwd"\s+value="` + portRangePattern + `"`)

// portForwardURLs lists all port forwarding endpoints.
// IPv4 and IPv6 must both be registered for dual-stack support.
var portForwardURLs = []string{
	"http://10.31.33.7/fwd",
	"http://[2001:db8::7]/fwd",
}

// portForwardData is the data persisted to the port forward JSON file.
type portForwardData struct {
	Ports []uint16 `json:"ports"`
}

// PortForward registers a forwarded port with the Cryptostorm port forwarding server
// and returns the active forwarded ports. The server returns plain text listing
// current forwardings. We POST the desired port and parse the response.
// Valid port range is 30000-65535.
// See: https://cryptostorm.is/portfwd
func (p *Provider) PortForward(ctx context.Context, objects utils.PortForwardObjects) (
	internalToExternalPorts map[uint16]uint16, err error,
) {
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Determine the port to request:
	// 1. Use VPN_PORT_FORWARDING_LISTENING_PORTS[0] if set (non-zero).
	// 2. Otherwise try to read a previously persisted port.
	// 3. Otherwise return an error (Cryptostorm does not auto-assign ports).
	var listeningPort uint16
	if len(objects.ListeningPorts) > 0 && objects.ListeningPorts[0] != 0 {
		listeningPort = objects.ListeningPorts[0]
	}
	if listeningPort == 0 {
		data, err := readPortForwardData(p.portForwardPath)
		if err != nil {
			return nil, fmt.Errorf("reading persisted port forward data: %w", err)
		}
		if len(data.Ports) > 0 {
			listeningPort = data.Ports[0]
		}
	}

	if listeningPort == 0 {
		return nil, fmt.Errorf("port forwarding not supported: set VPN_PORT_FORWARDING_LISTENING_PORTS to a value between 30000 and 65535")
	}

	postBody := "port=" + strconv.FormatUint(uint64(listeningPort), 10)

	// Register the port with both IPv4 and IPv6 endpoints.
	// The IPv6 endpoint may not be reachable if the tunnel has no IPv6,
	// so we log a warning rather than failing hard.
	requestedFound := false
	for _, url := range portForwardURLs {
		found, err := p.registerPort(ctx, objects.Client, url, postBody, listeningPort, objects)
		if err != nil {
			if url == portForwardURLs[0] {
				// IPv4 failure is fatal.
				return nil, err
			}
			// IPv6 failure is a warning only.
			objects.Logger.Warn("IPv6 port forward registration failed (" + url + "): " + err.Error())
			continue
		}
		if found {
			requestedFound = true
		}
	}

	if !requestedFound {
		return nil, fmt.Errorf("port forwarding not supported: requested port %d not found in server response", listeningPort)
	}

	p.forwardedPort = listeningPort
	internalToExternalPorts = map[uint16]uint16{listeningPort: listeningPort}

	// Persist so the next restart can reuse this port without re-requesting.
	if err := writePortForwardData(p.portForwardPath, portForwardData{Ports: []uint16{listeningPort}}); err != nil {
		return nil, fmt.Errorf("persisting port forward data: %w", err)
	}

	return internalToExternalPorts, nil
}

// registerPort POSTs the port to a single forwarding endpoint and returns
// whether the requested port was confirmed in the response.
func (p *Provider) registerPort(ctx context.Context, client *http.Client,
	url, postBody string, listeningPort uint16, objects utils.PortForwardObjects,
) (requestedFound bool, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(postBody))
	if err != nil {
		return false, fmt.Errorf("creating HTTP request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("sending HTTP request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP status code not OK: %d %s",
			response.StatusCode, response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body: %w", err)
	}

	// Parse forwarded ports from the response. The server returns HTML to
	// Go's HTTP client but plain text to curl, so we try both formats.
	bodyStr := string(body)
	matches := regexForwardPlainText.FindAllStringSubmatch(bodyStr, -1)
	if len(matches) == 0 {
		matches = regexForwardHTML.FindAllStringSubmatch(bodyStr, -1)
	}
	if len(matches) == 0 {
		return false, fmt.Errorf("port forwarding not supported: no active port forwards found in response")
	}

	// The server response lists all currently active forwards for this session,
	// which may include stale ports from prior runs. Delete any that are not
	// the one we requested, then verify ours is present.
	const base, bitSize = 10, 16
	for _, match := range matches {
		portUint64, err := strconv.ParseUint(match[1], base, bitSize)
		if err != nil {
			return false, fmt.Errorf("parsing port number %q: %w", match[1], err)
		}
		port := uint16(portUint64)
		if port == listeningPort {
			requestedFound = true
			continue
		}
		// Best-effort delete; log but don't fail if it errors.
		if err := p.deletePortFromURL(ctx, client, url, port); err != nil {
			objects.Logger.Warn("deleting stale port forward " +
				strconv.FormatUint(uint64(port), 10) + " from " + url + ": " + err.Error())
		}
	}

	return requestedFound, nil
}

func (p *Provider) KeepPortForward(ctx context.Context,
	objects utils.PortForwardObjects,
) (err error) {
	// Cryptostorm port assignments persist for the session; no keepalive needed.
	<-ctx.Done()

	// Best-effort deregister on teardown. Use a fresh context since the
	// original is already cancelled.
	if p.forwardedPort != 0 {
		const deleteTimeout = 5 * time.Second
		deleteCtx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
		defer cancel()
		for _, url := range portForwardURLs {
			if err := p.deletePortFromURL(deleteCtx, objects.Client, url, p.forwardedPort); err != nil {
				objects.Logger.Warn("deregistering port forward on teardown from " + url + ": " + err.Error())
			}
		}
		p.forwardedPort = 0
	}

	return ctx.Err()
}

func (p *Provider) deletePortFromURL(ctx context.Context, client *http.Client, url string, port uint16) error {
	body := strings.NewReader("delfwd=" + strconv.FormatUint(uint64(port), 10))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("creating delete request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("sending delete request: %w", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status code not OK: %d %s",
			response.StatusCode, response.Status)
	}
	return nil
}

func readPortForwardData(path string) (data portForwardData, err error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return data, nil
	} else if err != nil {
		return data, err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		_ = file.Close()
		return data, err
	}

	return data, file.Close()
}

func writePortForwardData(path string, data portForwardData) (err error) {
	const dirPermission = fs.FileMode(0o755)
	if err := os.MkdirAll(filepath.Dir(path), dirPermission); err != nil {
		return err
	}

	const permission = fs.FileMode(0o644)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, permission)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		_ = file.Close()
		return err
	}

	return file.Close()
}
