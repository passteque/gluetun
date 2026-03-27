package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/models"
)

type echoip struct {
	client *http.Client
	url    string
}

func newEchoip(client *http.Client, url string) *echoip {
	return &echoip{
		client: client,
		url:    url,
	}
}

func (e *echoip) String() string {
	s := e.url
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	return s
}

func (e *echoip) CanFetchAnyIP() bool {
	return true
}

func (e *echoip) Token() string {
	return ""
}

// FetchInfo obtains information on the ip address provided
// using the echoip API at the url given. If the ip is the zero value,
// the public IP address of the machine is used as the IP.
func (e *echoip) FetchInfo(ctx context.Context, ip netip.Addr) (
	result models.PublicIP, err error,
) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := e.url + "/json"
	if ip.IsValid() {
		url += "?ip=" + ip.String()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}

	response, err := e.client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return result, fmt.Errorf("%w from %s: %s",
			ErrTooManyRequests, url, response.Status)
	default:
		return result, fmt.Errorf("%w from %s: %s",
			ErrBadHTTPStatus, url, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	var data struct {
		IP         netip.Addr `json:"ip,omitempty"`
		Country    string     `json:"country,omitempty"`
		RegionName string     `json:"region_name,omitempty"`
		ZipCode    string     `json:"zip_code,omitempty"`
		City       string     `json:"city,omitempty"`
		Latitude   float32    `json:"latitude,omitempty"`
		Longitude  float32    `json:"longitude,omitempty"`
		Hostname   string     `json:"hostname,omitempty"`
		// Timezone in the form America/Montreal
		Timezone string `json:"time_zone,omitempty"`
		AsnOrg   string `json:"asn_org,omitempty"`
	}
	err = decoder.Decode(&data)
	if err != nil {
		return result, fmt.Errorf("decoding response: %w", err)
	}

	result = models.PublicIP{
		IP:           data.IP,
		Region:       data.RegionName,
		Country:      data.Country,
		City:         data.City,
		Hostname:     data.Hostname,
		Location:     fmt.Sprintf("%f,%f", data.Latitude, data.Longitude),
		Organization: data.AsnOrg,
		PostalCode:   data.ZipCode,
		Timezone:     data.Timezone,
	}
	return result, nil
}
