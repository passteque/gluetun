package azirevpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const apiBaseURL = "https://api.azirevpn.com/v3"

type apiHTTPStatusError struct {
	statusCode int
	status     string
	body       string
}

func (e *apiHTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP status code not OK: %d %s: %s",
		e.statusCode, e.status, e.body)
}

func (e *apiHTTPStatusError) StatusCode() int {
	return e.statusCode
}

func (e *apiHTTPStatusError) Body() string {
	return e.body
}

func statusCodeOf(err error) (statusCode int, ok bool) {
	var statusErr *apiHTTPStatusError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	return statusErr.statusCode, true
}

type responseEnvelope struct {
	Status    string          `json:"status"`
	Message   string          `json:"message,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Locations json.RawMessage `json:"locations,omitempty"`
}

type location struct {
	Name    string `json:"name"`
	City    string `json:"city"`
	Country string `json:"country"`
	ISO     string `json:"iso"`
	Pool    string `json:"pool"`
	PubKey  string `json:"pubkey"`
}

type ipData struct {
	ID          string   `json:"id"`
	IPv4Address string   `json:"ipv4_address"`
	IPv4Netmask int      `json:"ipv4_netmask"`
	IPv6Address string   `json:"ipv6_address"`
	IPv6Netmask int      `json:"ipv6_netmask"`
	DNS         []string `json:"dns"`
	DeviceName  string   `json:"device_name"`
	Keys        []ipKey  `json:"keys"`
}

type ipKey struct {
	Key       string `json:"key"`
	CreatedAt int64  `json:"created_at"`
}

type portForwardData struct {
	InternalIPv4 string        `json:"internal_ipv4"`
	InternalIPv6 string        `json:"internal_ipv6"`
	Ports        []portForward `json:"ports,omitempty"`
	Port         *uint16       `json:"port,omitempty"`
	Hidden       bool          `json:"hidden"`
	ExpiresAt    int64         `json:"expires_at"`
}

type portForward struct {
	Port      uint16 `json:"port"`
	Hidden    bool   `json:"hidden"`
	ExpiresAt int64  `json:"expires_at"`
}

type persistedData struct {
	InternalIPv4  string `json:"internal_ipv4,omitempty"`
	Port          uint16 `json:"port,omitempty"`
	PortExpiresAt int64  `json:"port_expires_at,omitempty"`
}

func readPersistedData(dataPath string) (data persistedData, err error) {
	file, err := os.Open(dataPath)
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

func writePersistedData(dataPath string, data persistedData) (err error) {
	const permission = fs.FileMode(0o600)
	file, err := os.OpenFile(dataPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, permission)
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

func (p *Provider) doAPIRequest(ctx context.Context, client *http.Client,
	method, path string, query url.Values, requestBody any, responseData any,
) (err error) {
	if p.token == "" {
		return fmt.Errorf("AZIREVPN_TOKEN is required")
	}

	requestURL, err := url.Parse(apiBaseURL + path)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if requestBody != nil {
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("doing request: %w", err)
	}
	defer response.Body.Close()

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &apiHTTPStatusError{
			statusCode: response.StatusCode,
			status:     response.Status,
			body:       strings.TrimSpace(string(responseBytes)),
		}
	}

	if responseData == nil || len(responseBytes) == 0 {
		return nil
	}

	if err := json.Unmarshal(responseBytes, responseData); err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}

	return nil
}

func (p *Provider) listPortForwardings(ctx context.Context,
	client *http.Client, internalIPv4 string,
) (data portForwardData, err error) {
	query := make(url.Values)
	query.Set("internal_ipv4", internalIPv4)

	var envelope responseEnvelope
	err = p.doAPIRequest(ctx, client, http.MethodGet, "/portforwardings", query, nil, &envelope)
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(envelope.Data, &data)
	if err != nil {
		return data, fmt.Errorf("decoding port forwarding data: %w", err)
	}

	return data, nil
}

func (p *Provider) createPortForwarding(ctx context.Context,
	client *http.Client, internalIPv4 string,
) (data portForwardData, err error) {
	requestBody := map[string]string{"internal_ipv4": internalIPv4}

	var envelope responseEnvelope
	err = p.doAPIRequest(ctx, client, http.MethodPost, "/portforwardings", nil, requestBody, &envelope)
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(envelope.Data, &data)
	if err != nil {
		return data, fmt.Errorf("decoding created port forwarding data: %w", err)
	}

	return data, nil
}

func (p *Provider) renewPortForwarding(ctx context.Context,
	client *http.Client, internalIPv4 string, port uint16,
) (data portForwardData, err error) {
	requestBody := map[string]any{
		"internal_ipv4": internalIPv4,
		"port":          port,
		"expires_in":    365,
	}

	var envelope responseEnvelope
	err = p.doAPIRequest(ctx, client, http.MethodPut, "/portforwardings", nil, requestBody, &envelope)
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(envelope.Data, &data)
	if err != nil {
		return data, fmt.Errorf("decoding renewed port forwarding data: %w", err)
	}

	return data, nil
}

func (p *Provider) deletePortForwarding(ctx context.Context,
	client *http.Client, internalIPv4 string, port uint16,
) (err error) {
	requestBody := map[string]any{
		"internal_ipv4": internalIPv4,
		"port":          port,
	}

	return p.doAPIRequest(ctx, client, http.MethodDelete,
		"/portforwardings", nil, requestBody, nil)
}
