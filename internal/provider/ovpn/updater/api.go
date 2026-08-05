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
	IP     netip.Addr `json:"ip"`
	Ptr    string     `json:"ptr"` // hostname
	Online bool       `json:"online"`
	// PublicKey is for the Standard Shared Entry Point
	PublicKey string `json:"public_key"`
	// PublicKeyIPv4 is for the Public / Dedicated IP Entry Point
	PublicKeyIPv4         string   `json:"public_key_ipv4"`
	WireguardPorts        []uint16 `json:"wireguard_ports"`
	MultiHopOpenvpnPort   uint16   `json:"multihop_openvpn_port"`
	MultiHopWireguardPort uint16   `json:"multihop_wireguard_port"`
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

func (a *apiDataCenter) validate() (err error) {
	conditionalErrors := []conditionalError{
		{err: "city is not set", condition: a.City == ""},
		{err: "country name is not set", condition: a.CountryName == ""},
		{err: "servers array is not set", condition: len(a.Servers) == 0},
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

func (a *apiServer) validate() (err error) {
	const defaultWireguardPort = 9929
	conditionalErrors := []conditionalError{
		{err: "ip address is not set", condition: !a.IP.IsValid()},
		{err: "hostname field is not set", condition: a.Ptr == ""},
		{err: "public key field is not set", condition: a.PublicKey == ""},
		{err: "public key IPv4 field is not set", condition: a.PublicKeyIPv4 == ""},
		{err: "wireguard ports array is not set", condition: len(a.WireguardPorts) == 0},
		{
			err:       "wireguard port is not the default 9929",
			condition: len(a.WireguardPorts) != 1 || a.WireguardPorts[0] != defaultWireguardPort,
		},
		{err: "multihop OpenVPN port is not set", condition: a.MultiHopOpenvpnPort == 0},
		{err: "multihop WireGuard port is not set", condition: a.MultiHopWireguardPort == 0},
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
	err       string
	condition bool
}

func collectErrors(conditionalErrors []conditionalError) (err error) {
	errs := make([]string, 0, len(conditionalErrors))
	for _, conditionalError := range conditionalErrors {
		if !conditionalError.condition {
			continue
		}
		errs = append(errs, conditionalError.err)
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.New(strings.Join(errs, "; "))
}
