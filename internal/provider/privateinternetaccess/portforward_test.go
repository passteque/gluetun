package privateinternetaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPIAServerName = "vancouver439"

func Test_fetchToken(t *testing.T) {
	t.Parallel()

	type receivedRequest struct {
		method   string
		username string
		password string
	}
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			responseWriter.WriteHeader(http.StatusBadRequest)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			responseWriter.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- receivedRequest{
			method:   request.Method,
			username: form.Get("username"),
			password: form.Get("password"),
		}
		responseWriter.Header().Set("Content-Type", "application/json")
		_, _ = responseWriter.Write([]byte(`{"token":"test-token"}`))
	}))
	t.Cleanup(server.Close)

	token, err := fetchTokenFromURL(context.Background(), server.Client(),
		server.URL, "test-user", "test-password")
	require.NoError(t, err)

	request := <-received
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, "test-user", request.username)
	assert.Equal(t, "test-password", request.password)
	assert.Equal(t, "test-token", token)
}

func Test_PortForward_inputValidation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		objects    utils.PortForwardObjects
		errMessage string
	}{
		"server_name_not_set": {
			errMessage: "server name cannot be empty",
		},
		"gateway_not_set": {
			objects: utils.PortForwardObjects{
				ServerName: testPIAServerName,
			},
			errMessage: "gateway is not set",
		},
		"username_not_set": {
			objects: utils.PortForwardObjects{
				ServerName: testPIAServerName,
				Gateway:    netip.MustParseAddr("10.13.161.1"),
			},
			errMessage: "username is not set",
		},
		"password_not_set": {
			objects: utils.PortForwardObjects{
				ServerName: testPIAServerName,
				Gateway:    netip.MustParseAddr("10.13.161.1"),
				Username:   "username",
			},
			errMessage: "password is not set",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider := &Provider{}

			_, err := provider.PortForward(context.Background(), testCase.objects)

			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_KeepPortForward_inputValidation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		objects    utils.PortForwardObjects
		errMessage string
	}{
		"server_name_not_set": {
			errMessage: "server name cannot be empty",
		},
		"gateway_not_set": {
			objects: utils.PortForwardObjects{
				ServerName: testPIAServerName,
			},
			errMessage: "gateway is not set",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider := &Provider{}

			err := provider.KeepPortForward(context.Background(), testCase.objects)

			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_findAPIIP_triesProviderGatewayFirst(t *testing.T) {
	t.Parallel()

	gateway := netip.MustParseAddr("10.13.161.1")
	requestedHosts := make([]string, 0, 1)
	client := &http.Client{
		Transport: piaRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requestedHosts = append(requestedHosts, request.URL.Host)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		}),
	}

	apiIP, err := findAPIIP(t.Context(), client, gateway)
	require.NoError(t, err)
	assert.Equal(t, gateway, apiIP)
	assert.Equal(t, []string{"10.13.161.1:19999"}, requestedHosts)
}

func Test_findAPIIP_fallsBackToLegacyGateway(t *testing.T) {
	t.Parallel()

	gateway := netip.MustParseAddr("10.13.161.1")
	requestedHosts := make([]string, 0, 2)
	client := &http.Client{
		Transport: piaRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requestedHosts = append(requestedHosts, request.URL.Host)
			if request.URL.Host == "10.13.161.1:19999" {
				return nil, errors.New("direct gateway unavailable")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		}),
	}

	apiIP, err := findAPIIP(t.Context(), client, gateway)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("10.13.128.1"), apiIP)
	assert.Equal(t, []string{"10.13.161.1:19999", "10.13.128.1:19999"}, requestedHosts)
}

func Test_findAPIIP_rejectsUnsupportedGateway(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		gateway    netip.Addr
		errMessage string
	}{
		"not_set": {
			errMessage: "gateway is not set",
		},
		"unspecified": {
			gateway:    netip.IPv4Unspecified(),
			errMessage: "gateway is unspecified",
		},
		"ipv6": {
			gateway:    netip.MustParseAddr("2001:db8::1"),
			errMessage: "gateway is IPv6, which PIA registration does not support",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := findAPIIP(t.Context(), nil, testCase.gateway)

			require.Error(t, err)
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_readPIAPortForwardData_restrictsPermissionsOnReuse(t *testing.T) {
	t.Parallel()

	expectedData := piaPortForwardData{
		Port:       12345,
		Token:      "secret-token",
		Signature:  "signature",
		Expiration: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}
	contents, err := json.Marshal(expectedData)
	require.NoError(t, err)
	path := t.TempDir() + "/pia.json"
	//nolint:gosec // Test begins with intentionally broad permissions.
	require.NoError(t, os.WriteFile(path, contents, 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	data, err := readPIAPortForwardData(path)
	require.NoError(t, err)
	assert.Equal(t, expectedData, data)

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
}

func Test_writePIAPortForwardData_restrictsPermissions(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/pia.json"
	//nolint:gosec // Test begins with intentionally broad permissions.
	require.NoError(t, os.WriteFile(path, []byte("old data"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	err := writePIAPortForwardData(path, piaPortForwardData{Token: "secret"})
	require.NoError(t, err)

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
}

func Test_unpackPayload(t *testing.T) {
	t.Parallel()

	const exampleToken = "token"
	const examplePort = 2000
	exampleExpiration := time.Unix(1000, 0).UTC()

	testCases := map[string]struct {
		payload    string
		port       uint16
		token      string
		expiration time.Time
		err        error
	}{
		"valid payload": {
			payload:    makePIAPayload(t, exampleToken, examplePort, exampleExpiration),
			port:       examplePort,
			token:      exampleToken,
			expiration: exampleExpiration,
			err:        nil,
		},
		"invalid base64 payload": {
			payload: "invalid",
			err:     errors.New("illegal base64 data at input byte 4: for payload: invalid"),
		},
		"invalid json payload": {
			payload: base64.StdEncoding.EncodeToString([]byte{1}),
			err:     errors.New("invalid character '\\x01' looking for beginning of value: for data: \x01"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			port, token, expiration, err := unpackPayload(testCase.payload)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, testCase.port, port)
			assert.Equal(t, testCase.token, token)
			assert.Equal(t, testCase.expiration, expiration)
		})
	}
}

func makePIAPayload(t *testing.T, token string, port uint16, expiration time.Time) (payload string) {
	t.Helper()

	data := piaPayload{
		Token:      token,
		Port:       port,
		Expiration: expiration,
	}

	b, err := json.Marshal(data)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(b)
}

func Test_replaceInString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		s             string
		substitutions map[string]string
		result        string
	}{
		"empty": {},
		"multiple replacements": {
			s: "https://test.com/username/password/",
			substitutions: map[string]string{
				"username": "xxx",
				"password": "yyy",
			},
			result: "https://test.com/xxx/yyy/",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := replaceInString(testCase.s, testCase.substitutions)
			assert.Equal(t, testCase.result, result)
		})
	}
}
