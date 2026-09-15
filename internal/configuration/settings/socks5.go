package settings

import (
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Socks5 contains settings to configure the Socks5 proxy server.
type Socks5 struct {
	Enabled          *bool
	ListeningAddress string
	Username         *string
	Password         *string
	// AllowedCIDRs are the client CIDR networks allowed to use the
	// SOCKS5 proxy server, each entry being a CIDR string such as
	// "192.168.1.2/32" or "10.0.0.0/8". If left unset, all client IPs
	// are allowed.
	AllowedCIDRs []string
}

func (s Socks5) validate() (err error) {
	err = validate.ListeningAddress(s.ListeningAddress, os.Getuid())
	if err != nil {
		return fmt.Errorf("server listening address is not valid: %w", err)
	}

	switch {
	case *s.Username != "" && *s.Password == "":
		return errors.New("password must be set if username is set")
	case *s.Username == "" && *s.Password != "":
		return errors.New("username must be set if password is set")
	}

	for _, allowedCIDR := range s.AllowedCIDRs {
		if _, err = netip.ParsePrefix(allowedCIDR); err != nil {
			return fmt.Errorf("parsing allowed CIDR: %w", err)
		}
	}

	return nil
}

func (s *Socks5) copy() (copied Socks5) {
	return Socks5{
		Enabled:          gosettings.CopyPointer(s.Enabled),
		ListeningAddress: s.ListeningAddress,
		Username:         gosettings.CopyPointer(s.Username),
		Password:         gosettings.CopyPointer(s.Password),
		AllowedCIDRs:     gosettings.CopySlice(s.AllowedCIDRs),
	}
}

func (s *Socks5) overrideWith(other Socks5) {
	s.Enabled = gosettings.OverrideWithPointer(s.Enabled, other.Enabled)
	s.ListeningAddress = gosettings.OverrideWithComparable(s.ListeningAddress, other.ListeningAddress)
	s.Username = gosettings.OverrideWithPointer(s.Username, other.Username)
	s.Password = gosettings.OverrideWithPointer(s.Password, other.Password)
	s.AllowedCIDRs = gosettings.OverrideWithSlice(s.AllowedCIDRs, other.AllowedCIDRs)
}

func (s *Socks5) setDefaults() {
	s.Enabled = gosettings.DefaultPointer(s.Enabled, false)
	s.ListeningAddress = gosettings.DefaultComparable(s.ListeningAddress, ":1080")
	s.Username = gosettings.DefaultPointer(s.Username, "")
	s.Password = gosettings.DefaultPointer(s.Password, "")
	s.AllowedCIDRs = gosettings.DefaultSlice(s.AllowedCIDRs, []string{})
}

func (s Socks5) String() string {
	return s.toLinesNode().String()
}

func (s Socks5) toLinesNode() (node *gotree.Node) {
	node = gotree.New("SOCKS5 proxy server settings:")
	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(s.Enabled))
	if !*s.Enabled {
		return node
	}

	node.Appendf("Listening address: %s", s.ListeningAddress)
	if *s.Username != "" || *s.Password != "" {
		node.Appendf("Username: %s", *s.Username)
		node.Appendf("Password: %s", gosettings.ObfuscateKey(*s.Password))
	}
	if len(s.AllowedCIDRs) > 0 {
		allowedCIDRsNode := node.Appendf("Allowed IP CIDRs:")
		for _, allowedCIDR := range s.AllowedCIDRs {
			allowedCIDRsNode.Append(allowedCIDR)
		}
	}
	return node
}

func (s *Socks5) read(r *reader.Reader) (err error) {
	s.Enabled, err = r.BoolPtr("SOCKS5_ENABLED")
	if err != nil {
		return err
	}

	s.ListeningAddress = r.String("SOCKS5_LISTENING_ADDRESS")
	s.Username = r.Get("SOCKS5_USER", reader.ForceLowercase(false))
	s.Password = r.Get("SOCKS5_PASSWORD", reader.ForceLowercase(false))
	s.AllowedCIDRs = r.CSV("SOCKS5_ALLOWED_CIDRS")

	return nil
}
