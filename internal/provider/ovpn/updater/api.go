package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

type apiData struct {
	Success     bool            `json:"success"`
	DataCenters []apiDataCenter `json:"datacenters"`
}

type apiDataCenter struct {
	City        string      `json:"city"`
	CountryName string      `json:"country_name"`
	Servers     []apiServer `json:"servers"`
}

type apiServer struct {
	IP                    netip.Addr `json:"ip"`
	Ptr                   string     `json:"ptr"` // hostname
	Online                bool       `json:"online"`
	PublicKey             string     `json:"public_key"`
	WireguardPorts        []uint16   `json:"wireguard_ports"`
	MultiHopOpenvpnPort   uint16     `json:"multihop_openvpn_port"`
	MultiHopWireguardPort uint16     `json:"multihop_wireguard_port"`
}

func fetchAPI(ctx context.Context, client *http.Client) (
	data apiData, err error,
) {
	const url = "https://www.ovpn.com/v2/api/client/entry"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return data, err
	}

	response, err := client.Do(request)
	if err != nil {
		return data, err
	}

	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return data, fmt.Errorf("HTTP response status code is not OK: %d %s",
			response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&data)
	if err != nil {
		_ = response.Body.Close()
		return data, fmt.Errorf("decoding response body: %w", err)
	}

	err = response.Body.Close()
	if err != nil {
		return data, fmt.Errorf("closing response body: %w", err)
	}

	return data, nil
}

var (
	ErrCityNotSet        = errors.New("city is not set")
	ErrCountryNameNotSet = errors.New("country name is not set")
	ErrServersNotSet     = errors.New("servers array is not set")
)

func (a *apiDataCenter) validate() (err error) {
	conditionalErrors := []conditionalError{
		{err: ErrCityNotSet, condition: a.City == ""},
		{err: ErrCountryNameNotSet, condition: a.CountryName == ""},
		{err: ErrServersNotSet, condition: len(a.Servers) == 0},
	}
	err = collectErrors(conditionalErrors)
	if err != nil {
		var dataCenterSetFields []string
		if a.CountryName != "" {
			dataCenterSetFields = append(dataCenterSetFields, a.CountryName)
		}
		if a.City != "" {
			dataCenterSetFields = append(dataCenterSetFields, a.City)
		}
		if len(dataCenterSetFields) == 0 {
			return err
		}
		return fmt.Errorf("data center %s: %w",
			strings.Join(dataCenterSetFields, ", "), err)
	}

	for i, server := range a.Servers {
		err = server.validate()
		if err != nil {
			return fmt.Errorf("datacenter %s, %s: server %d of %d: %w",
				a.CountryName, a.City, i+1, len(a.Servers), err)
		}
	}

	return nil
}

var (
	ErrIPFieldNotValid             = errors.New("ip address is not set")
	ErrHostnameFieldNotSet         = errors.New("hostname field is not set")
	ErrPublicKeyFieldNotSet        = errors.New("public key field is not set")
	ErrWireguardPortsNotSet        = errors.New("wireguard ports array is not set")
	ErrWireguardPortNotDefault     = errors.New("wireguard port is not the default 9929")
	ErrMultiHopOpenVPNPortNotSet   = errors.New("multihop OpenVPN port is not set")
	ErrMultiHopWireguardPortNotSet = errors.New("multihop WireGuard port is not set")
)

func (a *apiServer) validate() (err error) {
	const defaultWireguardPort = 9929
	conditionalErrors := []conditionalError{
		{err: ErrIPFieldNotValid, condition: !a.IP.IsValid()},
		{err: ErrHostnameFieldNotSet, condition: a.Ptr == ""},
		{err: ErrPublicKeyFieldNotSet, condition: a.PublicKey == ""},
		{err: ErrWireguardPortsNotSet, condition: len(a.WireguardPorts) == 0},
		{
			err:       ErrWireguardPortNotDefault,
			condition: len(a.WireguardPorts) != 1 || a.WireguardPorts[0] != defaultWireguardPort,
		},
		{err: ErrMultiHopOpenVPNPortNotSet, condition: a.MultiHopOpenvpnPort == 0},
		{err: ErrMultiHopWireguardPortNotSet, condition: a.MultiHopWireguardPort == 0},
	}
	err = collectErrors(conditionalErrors)
	switch {
	case err == nil:
		return nil
	case a.Ptr != "":
		return fmt.Errorf("server %s: %w", a.Ptr, err)
	case a.IP.IsValid():
		return fmt.Errorf("server %s: %w", a.IP.String(), err)
	default:
		return err
	}
}

type conditionalError struct {
	err       error
	condition bool
}

type joinedError struct {
	errs []error
}

func (e *joinedError) Unwrap() []error {
	return e.errs
}

func (e *joinedError) Error() string {
	errStrings := make([]string, len(e.errs))
	for i, err := range e.errs {
		errStrings[i] = err.Error()
	}
	return strings.Join(errStrings, "; ")
}

func collectErrors(conditionalErrors []conditionalError) (err error) {
	errs := make([]error, 0, len(conditionalErrors))
	for _, conditionalError := range conditionalErrors {
		if !conditionalError.condition {
			continue
		}
		errs = append(errs, conditionalError.err)
	}

	if len(errs) == 0 {
		return nil
	}

	return &joinedError{
		errs: errs,
	}
}
