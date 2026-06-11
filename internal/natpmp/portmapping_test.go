package natpmp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_Client_AddPortMapping(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ctx                       context.Context
		gateway                   netip.Addr
		protocol                  string
		internalPort              uint16
		requestedExternalPort     uint16
		lifetime                  time.Duration
		initialConnectionDuration time.Duration
		exchanges                 []udpExchange
		durationSinceStartOfEpoch time.Duration
		assignedInternalPort      uint16
		assignedExternalPort      uint16
		assignedLifetime          time.Duration
		errMessage                string
	}{
		"lifetime_too_long": {
			lifetime:   time.Duration(uint64(^uint32(0))+1) * time.Second,
			errMessage: "lifetime is too long: 4294967296 seconds must at most 4294967295 seconds",
		},
		"protocol_unknown": {
			lifetime:   time.Second,
			protocol:   "xyz",
			errMessage: "network protocol is unknown: xyz",
		},
		"rpc_error": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			protocol:                  "udp",
			internalPort:              123,
			requestedExternalPort:     456,
			lifetime:                  1200 * time.Second,
			initialConnectionDuration: time.Millisecond,
			exchanges:                 []udpExchange{{close: true}},
			errMessage: "executing remote procedure call: connection timeout: failed attempts: " +
				"read udp 127.0.0.1:[1-9][0-9]{0,4}->127.0.0.1:[1-9][0-9]{0,4}: i/o timeout \\(try 1\\)",
		},
		"add_udp": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			protocol:                  "udp",
			internalPort:              123,
			requestedExternalPort:     456,
			lifetime:                  1200 * time.Second,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x1, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x0, 0x81, 0x0, 0x0, 0x0, 0x13, 0xfe, 0xff, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			}},
			durationSinceStartOfEpoch: 0x13feff * time.Second,
			assignedInternalPort:      0x7b,
			assignedExternalPort:      0x1c8,
			assignedLifetime:          0x4b0 * time.Second,
		},
		"add_tcp": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			protocol:                  "tcp",
			internalPort:              123,
			requestedExternalPort:     456,
			lifetime:                  1200 * time.Second,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
				response: []byte{0x0, 0x82, 0x0, 0x0, 0x0, 0x14, 0x3, 0x21, 0x0, 0x7b, 0x1, 0xc8, 0x0, 0x0, 0x4, 0xb0},
			}},
			durationSinceStartOfEpoch: 0x140321 * time.Second,
			assignedInternalPort:      0x7b,
			assignedExternalPort:      0x1c8,
			assignedLifetime:          0x4b0 * time.Second,
		},
		"remove_udp": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			protocol:                  "udp",
			internalPort:              123,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x1, 0x0, 0x0, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				response: []byte{0x0, 0x81, 0x0, 0x0, 0x0, 0x14, 0x3, 0xd5, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			durationSinceStartOfEpoch: 0x1403d5 * time.Second,
			assignedInternalPort:      0x7b,
		},
		"remove_tcp": {
			ctx:                       context.Background(),
			gateway:                   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			protocol:                  "tcp",
			internalPort:              123,
			initialConnectionDuration: initialConnectionDuration,
			exchanges: []udpExchange{{
				request:  []byte{0x0, 0x2, 0x0, 0x0, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
				response: []byte{0x0, 0x82, 0x0, 0x0, 0x0, 0x14, 0x4, 0x96, 0x0, 0x7b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}},
			durationSinceStartOfEpoch: 0x140496 * time.Second,
			assignedInternalPort:      0x7b,
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

			durationSinceStartOfEpoch, assignedInternalPort,
				assignedExternalPort, assignedLifetime, err := client.AddPortMapping(testCase.ctx, testCase.gateway,
				testCase.protocol, testCase.internalPort,
				testCase.requestedExternalPort, testCase.lifetime)

			assert.Equal(t, testCase.durationSinceStartOfEpoch, durationSinceStartOfEpoch)
			assert.Equal(t, testCase.assignedInternalPort, assignedInternalPort)
			assert.Equal(t, testCase.assignedExternalPort, assignedExternalPort)
			assert.Equal(t, testCase.assignedLifetime, assignedLifetime)
			if testCase.errMessage != "" {
				assert.Regexp(t, "^"+testCase.errMessage+"$", err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
