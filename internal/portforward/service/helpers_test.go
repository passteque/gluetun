package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_portsToString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ports []uint16
		s     string
	}{
		"no_port": {
			s: "no port forwarded",
		},
		"one_port": {
			ports: []uint16{123},
			s:     "port forwarded is 123",
		},
		"two_ports": {
			ports: []uint16{123, 456},
			s:     "ports forwarded are 123 and 456",
		},
		"three_ports": {
			ports: []uint16{123, 456, 789},
			s:     "ports forwarded are 123, 456 and 789",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := portsToString(testCase.ports)

			assert.Equal(t, testCase.s, s)
		})
	}
}

func Test_externalInternalPortsToString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		internalToExternalPort map[uint16]uint16
		s                      string
	}{
		"no_port": {
			s: "no port forwarded",
		},
		"one_port": {
			internalToExternalPort: map[uint16]uint16{123: 123},
			s:                      "port forwarded is 123",
		},
		"two_ports": {
			internalToExternalPort: map[uint16]uint16{123: 123, 456: 456},
			s:                      "ports forwarded are 123 and 456",
		},
		"two_ports_different_internal_external": {
			internalToExternalPort: map[uint16]uint16{123: 124, 456: 457},
			s:                      "ports forwarded are 124 (internal port 123) and 457 (internal port 456)",
		},
		"three_ports": {
			internalToExternalPort: map[uint16]uint16{123: 123, 456: 456, 789: 789},
			s:                      "ports forwarded are 123, 456 and 789",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := portPairsToString(testCase.internalToExternalPort)

			assert.Equal(t, testCase.s, s)
		})
	}
}
