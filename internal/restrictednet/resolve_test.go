package restrictednet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Client_ResolveName(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ipv6Supported     bool
		upstreamResolvers []provider.Provider
		expectedAddresses []netip.Addr
		errorContains     string
		expectedDestIPs   []netip.Addr
		responder         func(host string, requestBody io.Reader) (*http.Response, error)
	}{
		"success_single_server_ipv4": {
			upstreamResolvers: []provider.Provider{{
				DoH: provider.DoHServer{
					URL:  "https://resolver-1.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				},
			}},
			expectedAddresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			expectedDestIPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			responder: func(_ string, requestBody io.Reader) (*http.Response, error) {
				wire := responseWireForQuery(t, requestBody, &dns.A{
					Hdr: dns.RR_Header{Name: "github.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{1, 1, 1, 1},
				})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			},
		},
		"fallback_between_servers": {
			upstreamResolvers: []provider.Provider{
				{
					DoH: provider.DoHServer{
						URL:  "https://resolver-1.local/dns-query",
						IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
					},
				},
				{
					DoH: provider.DoHServer{
						URL:  "https://resolver-2.local/dns-query",
						IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
					},
				},
			},
			expectedAddresses: []netip.Addr{netip.MustParseAddr("2.2.2.2")},
			expectedDestIPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
			responder: func(host string, requestBody io.Reader) (*http.Response, error) {
				if host == "resolver-1.local" ||
					len(host) > len("resolver-1.local:") && host[:len("resolver-1.local:")] == "resolver-1.local:" {
					return &http.Response{
						StatusCode: http.StatusBadGateway,
						Status:     "502 Bad Gateway",
						Body:       io.NopCloser(bytes.NewReader([]byte("bad gateway"))),
					}, nil
				}
				wire := responseWireForQuery(t, requestBody, &dns.A{
					Hdr: dns.RR_Header{Name: "github.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{2, 2, 2, 2},
				})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			},
		},
		"fallback_between_ips": {
			upstreamResolvers: []provider.Provider{{
				DoH: provider.DoHServer{
					URL:  "https://resolver.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
				},
			}},
			expectedAddresses: []netip.Addr{netip.MustParseAddr("1.1.1.2")},
			expectedDestIPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
			responder: func() func(host string, requestBody io.Reader) (*http.Response, error) {
				var calls atomic.Int32
				return func(_ string, requestBody io.Reader) (*http.Response, error) {
					if calls.Add(1) == 1 { // first call fails
						return &http.Response{
							StatusCode: http.StatusNotFound,
							Status:     "502 Bad Gateway",
							Body:       io.NopCloser(bytes.NewReader([]byte("bad gateway"))),
						}, nil
					}
					wire := responseWireForQuery(t, requestBody, &dns.A{
						Hdr: dns.RR_Header{Name: "github.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
						A:   net.IP{1, 1, 1, 2},
					})
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
				}
			}(), //nolint:bodyclose
		},
		"dns_rcode_error_servfail": {
			upstreamResolvers: []provider.Provider{{
				DoH: provider.DoHServer{
					URL:  "https://resolver.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				},
			}},
			errorContains:   "SERVFAIL",
			expectedDestIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			responder: func(_ string, requestBody io.Reader) (*http.Response, error) {
				queryWire, err := io.ReadAll(requestBody)
				require.NoError(t, err)
				query := new(dns.Msg)
				err = query.Unpack(queryWire)
				require.NoError(t, err)
				response := new(dns.Msg)
				response.SetReply(query)
				response.Rcode = dns.RcodeServerFailure
				wire, err := response.Pack()
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			},
		},
		"no_answer": {
			upstreamResolvers: []provider.Provider{{
				DoH: provider.DoHServer{
					URL:  "https://resolver.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				},
			}},
			expectedAddresses: nil,
			expectedDestIPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			responder: func(_ string, requestBody io.Reader) (*http.Response, error) {
				wire := responseWireForQuery(t, requestBody)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			},
		},
		"ipv6_preference": {
			ipv6Supported: true,
			upstreamResolvers: []provider.Provider{{
				DoH: provider.DoHServer{
					URL:  "https://resolver.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
					IPv6: []netip.Addr{netip.MustParseAddr("::1")},
				},
			}},
			expectedAddresses: []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
			expectedDestIPs: []netip.Addr{
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("127.0.0.1"),
			},
			responder: func(_ string, requestBody io.Reader) (*http.Response, error) {
				queryWire, err := io.ReadAll(requestBody)
				require.NoError(t, err)
				query := new(dns.Msg)
				err = query.Unpack(queryWire)
				require.NoError(t, err)
				if len(query.Question) > 0 && query.Question[0].Qtype == dns.TypeA {
					wire := responseWireForQuery(t, bytes.NewReader(queryWire))
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
				}
				wire := responseWireForQuery(t, bytes.NewReader(queryWire), &dns.AAAA{
					Hdr:  dns.RR_Header{Name: "github.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
				})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wire))}, nil
			},
		},
		"all_servers_fail": {
			upstreamResolvers: []provider.Provider{
				{DoH: provider.DoHServer{
					URL:  "https://resolver-1.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				}},
				{DoH: provider.DoHServer{
					URL:  "https://resolver-2.local/dns-query",
					IPv4: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
				}},
			},
			errorContains:   "resolving host",
			expectedDestIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
			responder: func(_ string, _ io.Reader) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Status:     "502 Bad Gateway",
					Body:       io.NopCloser(bytes.NewReader([]byte("bad gateway"))),
				}, nil
			},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			firewall := NewMockFirewall(ctrl)
			port := startTCPAccepter(t)

			for _, destinationIP := range testCase.expectedDestIPs {
				expectFirewallCallPair(firewall, t.Context(), destinationIP, port, nil, nil)
			}

			resolvers := make([]provider.Provider, len(testCase.upstreamResolvers))
			copy(resolvers, testCase.upstreamResolvers)
			for i := range resolvers {
				resolvers[i].DoH.URL = urlToHostnamePort(resolvers[i].DoH.URL, port)
			}

			settings := Settings{
				DefaultInterface:  "eth0",
				IPv6Supported:     ptrTo(testCase.ipv6Supported),
				Firewall:          firewall,
				UpstreamResolvers: resolvers,
				BaseTransport:     newInterceptTransport(testCase.responder),
			}
			client := New(settings)
			client.httpsPort = port

			addresses, err := client.ResolveName(t.Context(), "github.com")
			assert.Equal(t, testCase.expectedAddresses, addresses)
			if testCase.errorContains != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_Client_doHQuery(t *testing.T) {
	t.Parallel()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryWire, err := query.Pack()
	require.NoError(t, err)

	responseWire := responseWireForQuery(t, bytes.NewReader(queryWire), &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.IP{1, 1, 1, 1},
	})

	testCases := map[string]struct {
		response              *http.Response
		addFirewallRuleErr    error
		removeFirewallRuleErr error
		errorContains         string
		expectedIPs           []netip.Addr
	}{
		"success": {
			response:    &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseWire))},
			expectedIPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		},
		"http_status_not_ok": {
			response: &http.Response{
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Body:       io.NopCloser(bytes.NewReader([]byte("bad gateway"))),
			},
			errorContains: "response status code is 502 Bad Gateway",
		},
		"malformed_dns_response": {
			response: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("not-dns")),
			},
			errorContains: "parsing DoH response",
		},
		"cleanup_error": {
			response:              &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseWire))},
			removeFirewallRuleErr: errors.New("cleanup failed"),
			errorContains:         "cleaning up https connection: removing output traffic rule: cleanup failed",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			firewall := NewMockFirewall(ctrl)
			port := startTCPAccepter(t)

			expectFirewallCallPair(
				firewall,
				context.Background(),
				netip.MustParseAddr("127.0.0.1"),
				port,
				testCase.addFirewallRuleErr,
				testCase.removeFirewallRuleErr,
			)

			settings := Settings{
				DefaultInterface:  "eth0",
				IPv6Supported:     ptrTo(false),
				Firewall:          firewall,
				UpstreamResolvers: []provider.Provider{provider.Google()},
				BaseTransport: newInterceptTransport(func(_ string, _ io.Reader) (*http.Response, error) {
					return testCase.response, nil
				}),
			}
			client := New(settings)
			client.httpsPort = port

			dohURL, err := url.Parse(urlToHostnamePort("https://resolver.local/dns-query", port))
			require.NoError(t, err)

			message, err := client.doHQuery(
				context.Background(),
				queryWire,
				dohURL,
				netip.MustParseAddr("127.0.0.1"),
			)

			if testCase.errorContains != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.errorContains)
				return
			}

			require.NoError(t, err)
			addresses := answersToNetipAddrs(message)
			assert.Equal(t, testCase.expectedIPs, addresses)
		})
	}
}

func Test_answersToNetipAddrs(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		message  *dns.Msg
		expected []netip.Addr
	}{
		"nil_message": {},
		"no_answers": {
			message:  &dns.Msg{},
			expected: []netip.Addr{},
		},
		"a_record": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{1, 1, 1, 1},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		},
		"aaaa_record": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
		},
		"mixed_records": {
			message: &dns.Msg{Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.IP{1, 1, 1, 1},
				},
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
					AAAA: net.IP{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88},
				},
			}},
			expected: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")},
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
