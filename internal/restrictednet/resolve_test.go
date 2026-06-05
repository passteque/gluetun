package restrictednet

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_answersToNetipAddrs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		message    *dns.Msg
		expected   []netip.Addr
		errorIsNil bool
	}{
		"nil_message": {
			message:    nil,
			expected:   nil,
			errorIsNil: true,
		},
		"no_answers": {
			message:    &dns.Msg{},
			expected:   []netip.Addr{},
			errorIsNil: true,
		},
		"a_record": {
			message: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
						A:   net.IP{1, 1, 1, 1},
					},
				},
			},
			expected:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			errorIsNil: true,
		},
		"aaaa_record": {
			message: &dns.Msg{
				Answer: []dns.RR{
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
						AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
					},
				},
			},
			expected:   []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
			errorIsNil: true,
		},
		"mixed_records": {
			message: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
						A:   net.IP{1, 1, 1, 1},
					},
					&dns.AAAA{
						Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
						AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
					},
				},
			},
			expected:   []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")},
			errorIsNil: true,
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			addresses := answersToNetipAddrs(testCase.message)

			assert.Equal(t, testCase.expected, addresses)
		})
	}
}
