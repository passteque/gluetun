package restrictednet

import (
	"errors"

	"github.com/qdm12/dns/v2/pkg/provider"
)

type Settings struct {
	DefaultInterface  string
	IPv6Supported     *bool
	Firewall          Firewall
	UpstreamResolvers []provider.Provider
}

func (s *Settings) validate() error {
	switch {
	case s.DefaultInterface == "":
		return errors.New("default interface is not set")
	case s.IPv6Supported == nil:
		return errors.New("IPv6 support field is not set")
	case s.Firewall == nil:
		return errors.New("firewall is not set")
	case len(s.UpstreamResolvers) == 0:
		return errors.New("no upstream resolvers provided")
	}
	return nil
}
