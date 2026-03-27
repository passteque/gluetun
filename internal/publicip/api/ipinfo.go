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

type ipInfo struct {
	client *http.Client
	token  string
}

func newIPInfo(client *http.Client, token string) *ipInfo {
	return &ipInfo{
		client: client,
		token:  token,
	}
}

func (i *ipInfo) String() string {
	return string(IPInfo)
}

func (i *ipInfo) CanFetchAnyIP() bool {
	return true
}

func (i *ipInfo) Token() string {
	return i.token
}

// FetchInfo obtains information on the ip address provided
// using the ipinfo.io API. If the ip is the zero value, the public IP address
// of the machine is used as the IP.
func (i *ipInfo) FetchInfo(ctx context.Context, ip netip.Addr) (
	result models.PublicIP, err error,
) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := "https://ipinfo.io/"
	switch {
	case ip.Is6():
		url = "https://v6.ipinfo.io/" + ip.String()
	case ip.Is4():
		url = "https://ipinfo.io/" + ip.String()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	request.Header.Set("Authorization", "Bearer "+i.token)

	response, err := i.client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	if i.token != "" && response.StatusCode == http.StatusUnauthorized {
		return result, fmt.Errorf("%w: %s", ErrTokenNotValid, response.Status)
	}

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests, http.StatusForbidden:
		return result, fmt.Errorf("%w from %s: %d %s",
			ErrTooManyRequests, url, response.StatusCode, response.Status)
	default:
		return result, fmt.Errorf("%w from %s: %d %s",
			ErrBadHTTPStatus, url, response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	var data struct {
		IP       netip.Addr `json:"ip,omitempty"`
		Region   string     `json:"region,omitempty"`
		Country  string     `json:"country,omitempty"`
		City     string     `json:"city,omitempty"`
		Hostname string     `json:"hostname,omitempty"`
		Loc      string     `json:"loc,omitempty"`
		Org      string     `json:"org,omitempty"`
		Postal   string     `json:"postal,omitempty"`
		Timezone string     `json:"timezone,omitempty"`
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
		IP:           data.IP,
		Region:       data.Region,
		Country:      data.Country,
		City:         data.City,
		Hostname:     data.Hostname,
		Location:     data.Loc,
		Organization: data.Org,
		PostalCode:   data.Postal,
		Timezone:     data.Timezone,
	}
	return result, nil
}
