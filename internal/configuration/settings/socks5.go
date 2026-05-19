package settings

import (
	"errors"
	"fmt"
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

	return nil
}

func (s *Socks5) copy() (copied Socks5) {
	return Socks5{
		Enabled:          gosettings.CopyPointer(s.Enabled),
		ListeningAddress: s.ListeningAddress,
		Username:         gosettings.CopyPointer(s.Username),
		Password:         gosettings.CopyPointer(s.Password),
	}
}

func (s *Socks5) overrideWith(other Socks5) {
	s.Enabled = gosettings.OverrideWithPointer(s.Enabled, other.Enabled)
	s.ListeningAddress = gosettings.OverrideWithComparable(s.ListeningAddress, other.ListeningAddress)
	s.Username = gosettings.OverrideWithPointer(s.Username, other.Username)
	s.Password = gosettings.OverrideWithPointer(s.Password, other.Password)
}

func (s *Socks5) setDefaults() {
	s.Enabled = gosettings.DefaultPointer(s.Enabled, false)
	s.ListeningAddress = gosettings.DefaultComparable(s.ListeningAddress, ":1080")
	s.Username = gosettings.DefaultPointer(s.Username, "")
	s.Password = gosettings.DefaultPointer(s.Password, "")
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

	return nil
}
