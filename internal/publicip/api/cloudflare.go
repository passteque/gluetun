package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

type cloudflare struct {
	client *http.Client
}

func newCloudflare(client *http.Client) *cloudflare {
	return &cloudflare{
		client: client,
	}
}

func (c *cloudflare) String() string {
	return string(Cloudflare)
}

func (c *cloudflare) CanFetchAnyIP() bool {
	return false
}

func (c *cloudflare) Token() (token string) {
	return ""
}

// FetchInfo obtains information on the public IP address of the machine,
// and returns an error if the `ip` argument is set since the Cloudflare API
// can only be used to provide details about the current machine public IP.
func (c *cloudflare) FetchInfo(ctx context.Context, ip netip.Addr) (
	result models.PublicIP, err error,
) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	urlBase := "https://speed.cloudflare.com"
	url := urlBase + "/meta"
	if ip.IsValid() {
		return result, fmt.Errorf("%w: cloudflare cannot provide information on the arbitrary IP address %s",
			ErrServiceLimited, ip)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	request.Header.Add("Referer", urlBase) // returns HTTP 403 otherwise

	response, err := c.client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return result, fmt.Errorf("%w from %s: %d %s",
			ErrTooManyRequests, url, response.StatusCode, response.Status)
	default:
		return result, fmt.Errorf("%w from %s: %d %s",
			ErrBadHTTPStatus, url, response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	var data struct {
		Hostname       string     `json:"hostname,omitempty"`
		ClientIP       netip.Addr `json:"clientIp,omitempty"`
		ASOrganization string     `json:"asOrganization,omitempty"`
		Country        string     `json:"country,omitempty"`
		City           string     `json:"city,omitempty"`
		Region         string     `json:"region,omitempty"`
		PostalCode     string     `json:"postalCode,omitempty"`
		Latitude       string     `json:"latitude,omitempty"`
		Longitude      string     `json:"longitude,omitempty"`
	}
	if err := decoder.Decode(&data); err != nil {
		return result, fmt.Errorf("decoding response: %w", err)
	}

	countryCode := strings.ToLower(data.Country)
	country, ok := constants.CountryCodes()[countryCode]
	if ok {
		data.Country = country
	}

	result = models.PublicIP{
		IP:           data.ClientIP,
		Region:       data.Region,
		Country:      data.Country,
		City:         data.City,
		Hostname:     data.Hostname,
		Location:     data.Latitude + "," + data.Longitude,
		Organization: data.ASOrganization,
		PostalCode:   data.PostalCode,
		Timezone:     "", // no timezone
	}
	return result, nil
}
