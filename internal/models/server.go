package models

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/vpn"
)

type Server struct {
	VPN string `json:"vpn,omitempty"`
	// Surfshark: country is also used for multi-hop
	Country     string       `json:"country,omitempty"`
	Region      string       `json:"region,omitempty"`
	City        string       `json:"city,omitempty"`
	ISP         string       `json:"isp,omitempty"`
	Categories  []string     `json:"categories,omitempty"`
	Owned       bool         `json:"owned,omitempty"`
	Number      uint16       `json:"number,omitempty"`
	ServerName  string       `json:"server_name,omitempty"`
	Hostname    string       `json:"hostname,omitempty"`
	TCP         bool         `json:"tcp,omitempty"`
	UDP         bool         `json:"udp,omitempty"`
	OvpnX509    string       `json:"x509,omitempty"`
	RetroLoc    string       `json:"retroloc,omitempty"` // TODO remove in v4
	MultiHop    bool         `json:"multihop,omitempty"`
	WgPubKey    string       `json:"wgpubkey,omitempty"`
	Free        bool         `json:"free,omitempty"` // TODO v4 create a SubscriptionTier struct
	Premium     bool         `json:"premium,omitempty"`
	Stream      bool         `json:"stream,omitempty"` // TODO v4 create a Features struct
	SecureCore  bool         `json:"secure_core,omitempty"`
	Tor         bool         `json:"tor,omitempty"`
	PortForward bool         `json:"port_forward,omitempty"`
	Dedicated   bool         `json:"dedicated,omitempty"`
	Keep        bool         `json:"keep,omitempty"`
	IPs         []netip.Addr `json:"ips,omitempty"`
}

var (
	ErrVPNFieldEmpty           = errors.New("vpn field is empty")
	ErrHostnameFieldEmpty      = errors.New("hostname field is empty")
	ErrIPsFieldEmpty           = errors.New("ips field is empty")
	ErrNoNetworkProtocol       = errors.New("both TCP and UDP fields are false for OpenVPN")
	ErrNetworkProtocolSet      = errors.New("no network protocol should be set")
	ErrWireguardPublicKeyEmpty = errors.New("wireguard public key field is empty")
)

func (s *Server) HasMinimumInformation() (err error) {
	switch {
	case s.VPN == "":
		return fmt.Errorf("%w", ErrVPNFieldEmpty)
	case len(s.IPs) == 0:
		return fmt.Errorf("%w", ErrIPsFieldEmpty)
	case s.VPN == vpn.Wireguard && (s.TCP || s.UDP):
		return fmt.Errorf("%w", ErrNetworkProtocolSet)
	case s.VPN == vpn.OpenVPN && !s.TCP && !s.UDP:
		return fmt.Errorf("%w", ErrNoNetworkProtocol)
	case s.VPN == vpn.Wireguard && s.WgPubKey == "":
		return fmt.Errorf("%w", ErrWireguardPublicKeyEmpty)
	default:
		return nil
	}
}

func (s *Server) Equal(other Server) (equal bool) {
	if !ipsAreEqual(s.IPs, other.IPs) {
		return false
	}

	serverCopy := *s
	serverCopy.IPs = nil
	other.IPs = nil
	return reflect.DeepEqual(serverCopy, other)
}

func ipsAreEqual(a, b []netip.Addr) (equal bool) {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].Compare(b[i]) != 0 {
			return false
		}
	}

	return true
}

func (s *Server) Key() (key string) {
	var protocols []string
	if s.TCP {
		protocols = append(protocols, "tcp")
	}
	if s.UDP {
		protocols = append(protocols, "udp")
	}

	return fmt.Sprintf("%s-%s-%s", s.VPN, strings.Join(protocols, "-"), s.Hostname)
}
