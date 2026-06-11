package natpmp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_Client_rpc(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ctx                       context.Context
		gateway                   netip.Addr
		request                   []byte
		responseSize              uint
		initialConnectionDuration time.Duration
		exchanges                 []udpExchange
		expectedResponse          []byte
		errMessage                string
	}{
		"gateway_ip_unspecified": {
			gateway:    netip.IPv6Unspecified(),
			request:    []byte{0, 0},
			errMessage: "gateway IP is unspecified",
		},
		"request_too_small": {
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0},
			initialConnectionDuration: time.Nanosecond, // doesn't matter
			errMessage: `checking request: message size is too small: ` +
				`need at least 2 bytes and got 1 byte\(s\)`,
		},
		"write_error": {
			ctx:     context.Background(),
			gateway: netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request: []byte{0, 0},
			errMessage: `writing to connection: write udp ` +
				`127.0.0.1:[1-9][0-9]{0,4}->127.0.0.1:[1-9][0-9]{0,4}: ` +
				`i/o timeout`,
		},
		"call_error": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0, 1},
			initialConnectionDuration: time.Millisecond,
			exchanges: []udpExchange{
				{request: []byte{0, 1}, close: true},
			},
			errMessage: "connection timeout: failed attempts: " +
				"read udp 127.0.0.1:[1-9][0-9]{0,4}->127.0.0.1:[1-9][0-9]{0,4}: i/o timeout \\(try 1\\)",
		},
		"response_too_small": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0, 0},
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0, 0},
				response: []byte{1},
			}},
			errMessage: `checking response: response size is too small: ` +
				`need at least 4 bytes and got 1 byte\(s\)`,
		},
		"unexpected_response_size": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			responseSize:              5,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0, 1, 2, 3}, // size 4
			}},
			errMessage: `checking response: response size is unexpected: ` +
				`expected 5 bytes and got 4 byte\(s\)`,
		},
		"unknown_protocol_version": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			responseSize:              16,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x1, 0x82, 0x0, 0x0, 0x0, 0x14, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			errMessage: "checking response: protocol version is unknown: 1",
		},
		"unexpected_operation_code": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			responseSize:              16,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x0, 0x88, 0x0, 0x0, 0x0, 0x14, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			errMessage: "checking response: operation code is unexpected: expected 0x82 and got 0x88",
		},
		"failure_result_code": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			responseSize:              16,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x0, 0x82, 0x0, 0x11, 0x0, 0x14, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			errMessage: "checking response: result code: result code is unknown: 17",
		},
		"success": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			request:                   []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			responseSize:              16,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x0, 0x82, 0x0, 0x0, 0x0, 0x0, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			expectedResponse: []byte{0x0, 0x82, 0x0, 0x0, 0x0, 0x0, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			remoteAddress := launchUDPServer(t, testCase.exchanges)

			client := Client{
				serverPort:                uint16(remoteAddress.Port), //nolint:gosec
				initialConnectionDuration: testCase.initialConnectionDuration,
				maxRetries:                1,
			}

			response, err := client.rpc(testCase.ctx, testCase.gateway,
				testCase.request, testCase.responseSize)

			if testCase.errMessage != "" {
				assert.Regexp(t, "^"+testCase.errMessage+"$", err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedResponse, response)
		})
	}
}

func Test_dedupFailedAttempts(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		failedAttempts []string
		expected       string
	}{
		"empty": {},
		"single_attempt": {
			failedAttempts: []string{"test"},
			expected:       "test (try 1)",
		},
		"multiple_same_attempts": {
			failedAttempts: []string{"test", "test", "test"},
			expected:       "test (tries 1, 2, 3)",
		},
		"multiple_different_attempts": {
			failedAttempts: []string{"test1", "test2", "test3"},
			expected:       "test1 (try 1); test2 (try 2); test3 (try 3)",
		},
		"soup_mix": {
			failedAttempts: []string{"test1", "test2", "test1", "test3", "test2"},
			expected:       "test1 (tries 1, 3); test2 (tries 2, 5); test3 (try 4)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual := dedupFailedAttempts(testCase.failedAttempts)
			assert.Equal(t, testCase.expected, actual)
		})
	}
}
