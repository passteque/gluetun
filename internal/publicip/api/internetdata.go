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

type internetData struct {
	client       *http.Client
	token        string
	countryCodes map[string]string
}

func newInternetData(client *http.Client, token string) *internetData {
	return &internetData{
		client:       client,
		token:        token,
		countryCodes: constants.CountryCodes(),
	}
}

func (i *internetData) String() string {
	return string(InternetData)
}

func (i *internetData) CanFetchAnyIP() bool {
	return true
}

func (i *internetData) Token() string {
	return i.token
}

// FetchInfo obtains information on the ip address provided
// using the api.internetdata.io API. If the ip is the zero value,
// the public IP address of the machine is used as the IP.
// Without a token, the region, city, postal code and location are empty.
func (i *internetData) FetchInfo(ctx context.Context, ip netip.Addr) (
	result models.PublicIP, err error,
) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	const baseURL = "https://api.internetdata.io/"
	url := baseURL + "myip"
	if ip.IsValid() {
		url = baseURL + ip.String()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result, err
	}
	if i.token != "" {
		request.Header.Set("Authorization", "Bearer "+i.token)
	}

	response, err := i.client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()

	if i.token != "" && response.StatusCode == http.StatusUnauthorized {
		return result, fmt.Errorf("token is not valid: %s", response.Status)
	}

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return result, fmt.Errorf("%w from %s: %d %s",
			ErrTooManyRequests, url, response.StatusCode, response.Status)
	default:
		return result, fmt.Errorf("bad HTTP status received from %s: %d %s",
			url, response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	var data struct {
		IP       netip.Addr `json:"ip,omitempty"`
		Hostname string     `json:"hostname,omitempty"`
		Location struct {
			Country    string   `json:"country,omitempty"`
			Region     string   `json:"region,omitempty"`
			City       string   `json:"city,omitempty"`
			PostalCode string   `json:"postal_code,omitempty"`
			Latitude   *float64 `json:"latitude,omitempty"`
			Longitude  *float64 `json:"longitude,omitempty"`
			Timezone   string   `json:"timezone,omitempty"`
		} `json:"location"`
		ASN struct {
			Number uint32 `json:"asn,omitempty"`
			Name   string `json:"name,omitempty"`
		} `json:"asn"`
	}
	if err := decoder.Decode(&data); err != nil {
		return result, fmt.Errorf("decoding response: %w", err)
	}

	country := data.Location.Country
	if name, ok := i.countryCodes[strings.ToLower(country)]; ok {
		country = name
	}

	var location string
	if data.Location.Latitude != nil && data.Location.Longitude != nil {
		location = fmt.Sprintf("%f,%f", *data.Location.Latitude, *data.Location.Longitude)
	}

	var organization string
	if data.ASN.Number != 0 {
		organization = fmt.Sprintf("AS%d %s", data.ASN.Number, data.ASN.Name)
	}

	result = models.PublicIP{
		IP:           data.IP,
		Region:       data.Location.Region,
		Country:      country,
		City:         data.Location.City,
		Hostname:     data.Hostname,
		Location:     location,
		Organization: organization,
		PostalCode:   data.Location.PostalCode,
		Timezone:     data.Location.Timezone,
	}
	return result, nil
}
