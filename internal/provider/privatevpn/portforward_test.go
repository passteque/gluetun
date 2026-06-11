package privatevpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/stretchr/testify/assert"
)

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (s roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return s(r)
}

func Test_Provider_PortForward(t *testing.T) {
	t.Parallel()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	testCases := map[string]struct {
		ctx                     context.Context
		objects                 utils.PortForwardObjects
		internalToExternalPorts map[uint16]uint16
		errMessage              string
	}{
		"canceled context": {
			ctx: canceledCtx,
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return nil, r.Context().Err()
					}),
				},
			},
			errMessage: `sending HTTP request: Get ` +
				`"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10": ` +
				`context canceled`,
		},
		"http_error": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return nil, errors.New("test error")
					}),
				},
			},
			errMessage: `sending HTTP request: Get ` +
				`"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10": ` +
				`test error`,
		},
		"bad_status_code": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Status:     http.StatusText(http.StatusBadRequest),
						}, nil
					}),
				},
			},
			errMessage: "HTTP status code not OK: 400 Bad Request",
		},
		"empty_response": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewReader(nil)),
						}, nil
					}),
				},
			},
			errMessage: "decoding JSON response: unexpected end of JSON input; data is: ",
		},
		"invalid_JSON": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
						}, nil
					}),
				},
			},
			errMessage: "decoding JSON response: invalid character 'i' looking for " +
				"beginning of value; data is: invalid json",
		},
		"not_supported": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"supported":false}`)),
						}, nil
					}),
				},
			},
			errMessage: "port forwarding not supported for this VPN server",
		},
		"port_not_found": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"supported":true,"status":"no port here"}`)),
						}, nil
					}),
				},
			},
			errMessage: "port forwarded not found in status \"no port here\"",
		},
		"port_too_big": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"supported":true,"status":"Port 91527 UDP/TCP"}`)),
						}, nil
					}),
				},
			},
			errMessage: "parsing port: strconv.ParseUint: parsing \"91527\": value out of range",
		},
		"success": {
			ctx: context.Background(),
			objects: utils.PortForwardObjects{
				InternalIP: netip.AddrFrom4([4]byte{10, 10, 10, 10}),
				Client: &http.Client{
					Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
						assert.Equal(t,
							"https://connect.pvdatanet.com/v3/Api/port?ip[]=10.10.10.10",
							r.URL.String())
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"supported":true,"status":"Port 61527 UDP/TCP"}`)),
						}, nil
					}),
				},
			},
			internalToExternalPorts: map[uint16]uint16{61527: 61527},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := Provider{}
			ports, err := provider.PortForward(testCase.ctx,
				testCase.objects)

			assert.Equal(t, testCase.internalToExternalPorts, ports)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
