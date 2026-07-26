package protonvpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_portsMapToString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		previous map[uint16]uint16
		current  map[uint16]uint16
		s        string
	}{
		"no_change": {
			previous: map[uint16]uint16{37928: 37928},
			current:  map[uint16]uint16{37928: 37928},
			s:        "",
		},
		"symmetric_port_reassigned": {
			previous: map[uint16]uint16{37928: 37928},
			current:  map[uint16]uint16{37928: 60557},
			s:        "37928 -> 60557",
		},
		"multiple_ports_sorted_by_internal_port": {
			previous: map[uint16]uint16{56789: 111, 37928: 222},
			current:  map[uint16]uint16{56789: 333, 37928: 444},
			s:        "222 -> 444, 111 -> 333",
		},
		"only_changed_ports_reported": {
			previous: map[uint16]uint16{56789: 111, 37928: 222},
			current:  map[uint16]uint16{56789: 111, 37928: 444},
			s:        "222 -> 444",
		},
		"unknown_internal_port_skipped": {
			previous: map[uint16]uint16{},
			current:  map[uint16]uint16{37928: 60557},
			s:        "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := portsMapToString(testCase.previous, testCase.current)

			assert.Equal(t, testCase.s, s)
		})
	}
}
