package extract

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDataFromLines(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		lines      []string
		connection models.Connection
		errMessage string
	}{
		"success": {
			lines: []string{"bla", "proto tcp", "remote 1.2.3.4 1194 tcp", "dev tun6"},
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     1194,
				Protocol: constants.TCP,
			},
		},
		"extraction error": {
			lines:      []string{"bla", "proto bad", "remote 1.2.3.4 1194 tcp"},
			errMessage: "on line 2: extracting protocol from proto line: network protocol not supported: bad",
		},
		"only use first values found": {
			lines: []string{"proto udp", "proto tcp", "remote 1.2.3.4 443 tcp", "remote 5.2.3.4 1194 udp"},
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     443,
				Protocol: constants.UDP,
			},
		},
		"no IP found": {
			lines: []string{"proto tcp"},
			connection: models.Connection{
				Protocol: constants.TCP,
			},
			errMessage: "remote line not found",
		},
		"default TCP port": {
			lines: []string{"remote 1.2.3.4", "proto tcp"},
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     443,
				Protocol: constants.TCP,
			},
		},
		"default UDP port": {
			lines: []string{"remote 1.2.3.4", "proto udp"},
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     1194,
				Protocol: constants.UDP,
			},
		},
		"leading_whitespace": {
			lines: []string{"  proto tcp", "\tremote 1.2.3.4 443 tcp"},
			connection: models.Connection{
				IP:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:     443,
				Protocol: constants.TCP,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			connection, err := extractDataFromLines(testCase.lines)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.connection, connection)
		})
	}
}

func Test_extractDataFromLine(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		line       string
		ip         netip.Addr
		port       uint16
		protocol   string
		errMessage string
	}{
		"irrelevant line": {
			line: "bla",
		},
		"extract proto error": {
			line:       "proto bad",
			errMessage: "network protocol not supported",
		},
		"extract proto success": {
			line:     "proto tcp",
			protocol: constants.TCP,
		},
		"tcp-client": {
			line:     "proto tcp-client",
			protocol: constants.TCP,
		},
		"extract remote error": {
			line:       "remote bad",
			errMessage: "host is not an IP address",
		},
		"extract remote success": {
			line:     "remote 1.2.3.4 1194 udp",
			ip:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
			port:     1194,
			protocol: constants.UDP,
		},
		"extract_port_fail": {
			line:       "port a",
			errMessage: "port is not valid",
		},
		"extract_port_success": {
			line: "port 1194",
			port: 1194,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ip, port, protocol, err := extractDataFromLine(testCase.line)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.ip, ip)
			assert.Equal(t, testCase.port, port)
			assert.Equal(t, testCase.protocol, protocol)
		})
	}
}

func Test_extractProto(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		line     string
		protocol string
		err      error
	}{
		"fields error": {
			line: "proto one two",
			err:  errors.New("proto line has not 2 fields as expected: proto one two"),
		},
		"bad protocol": {
			line: "proto bad",
			err:  errors.New("network protocol not supported: bad"),
		},
		"udp": {
			line:     "proto udp",
			protocol: constants.UDP,
		},
		"tcp": {
			line:     "proto tcp",
			protocol: constants.TCP,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			protocol, err := extractProto(testCase.line)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.protocol, protocol)
		})
	}
}

func Test_extractRemote(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		line     string
		ip       netip.Addr
		port     uint16
		protocol string
		err      error
	}{
		"not enough fields": {
			line: "remote",
			err:  errors.New("remote line has not 2 fields as expected: remote"),
		},
		"too many fields": {
			line: "remote one two three four",
			err:  errors.New("remote line has not 2 fields as expected: remote one two three four"),
		},
		"host is not an IP": {
			line: "remote somehost.com",
			err:  errors.New("host is not an IP address: somehost.com"),
		},
		"only IP host": {
			line: "remote 1.2.3.4",
			ip:   netip.AddrFrom4([4]byte{1, 2, 3, 4}),
		},
		"port not an integer": {
			line: "remote 1.2.3.4 bad",
			err:  errors.New("port is not valid: remote 1.2.3.4 bad"),
		},
		"port is zero": {
			line: "remote 1.2.3.4 0",
			err:  errors.New("port is not valid: 0 must be between 1 and 65535"),
		},
		"port is minus one": {
			line: "remote 1.2.3.4 -1",
			err:  errors.New("port is not valid: -1 must be between 1 and 65535"),
		},
		"port is over 65535": {
			line: "remote 1.2.3.4 65536",
			err:  errors.New("port is not valid: 65536 must be between 1 and 65535"),
		},
		"IP host and port": {
			line: "remote 1.2.3.4 8000",
			ip:   netip.AddrFrom4([4]byte{1, 2, 3, 4}),
			port: 8000,
		},
		"invalid protocol": {
			line: "remote 1.2.3.4 8000 bad",
			err:  errors.New("parsing protocol from remote line: network protocol not supported: bad"),
		},
		"IP host and port and protocol": {
			line:     "remote 1.2.3.4 8000 udp",
			ip:       netip.AddrFrom4([4]byte{1, 2, 3, 4}),
			port:     8000,
			protocol: constants.UDP,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ip, port, protocol, err := extractRemote(testCase.line)

			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, testCase.ip, ip)
			assert.Equal(t, testCase.port, port)
			assert.Equal(t, testCase.protocol, protocol)
		})
	}
}
