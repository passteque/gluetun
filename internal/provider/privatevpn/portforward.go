package privatevpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
)

var regexPort = regexp.MustCompile(`[1-9][0-9]{0,4}`)

// PortForward obtains a VPN server side port forwarded from the PrivateVPN API.
// It returns 0 if all ports are to forwarded on a dedicated server IP.
func (p *Provider) PortForward(ctx context.Context, objects utils.PortForwardObjects) (
	internalToExternalPorts map[uint16]uint16, err error,
) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := "https://connect.pvdatanet.com/v3/Api/port?ip[]=" + objects.InternalIP.String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	response, err := objects.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sending HTTP request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code not OK: %d %s", response.StatusCode, response.Status)
	}

	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var data struct {
		Status    string `json:"status"`
		Supported bool   `json:"supported"`
	}
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		return nil, fmt.Errorf("decoding JSON response: %w; data is: %s",
			err, string(bytes))
	} else if !data.Supported {
		return nil, errors.New("port forwarding not supported for this VPN server")
	}

	portString := regexPort.FindString(data.Status)
	if portString == "" {
		return nil, fmt.Errorf("port forwarded not found in status %q", data.Status)
	}

	const base, bitSize = 10, 16
	portUint64, err := strconv.ParseUint(portString, base, bitSize)
	if err != nil {
		return nil, fmt.Errorf("parsing port: %w", err)
	}
	port := uint16(portUint64)
	return map[uint16]uint16{port: port}, nil
}

func (p *Provider) KeepPortForward(ctx context.Context,
	_ utils.PortForwardObjects,
) (err error) {
	<-ctx.Done()
	return ctx.Err()
}
