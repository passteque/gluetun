package portforward

import (
	"github.com/qdm12/gluetun/internal/portforward/service"
	"github.com/qdm12/gosettings"
)

type Settings struct {
	// VPNIsUp can be optionally set to signal the loop
	// the VPN is up (true) or down (false). If left to nil,
	// it is assumed the VPN is in the same previous state.
	VPNIsUp *bool
	Service service.Settings
}

// updateWith deep copies the receiving settings, overrides the copy with
// fields set in the partialUpdate argument, validates the new settings
// and returns them if they are valid, or returns an error otherwise.
// In all cases, the receiving settings are unmodified.
func (s Settings) updateWith(partialUpdate Settings) (updated Settings, err error) {
	updated = s.copy()
	updated.overrideWith(partialUpdate)
	err = updated.validate(*updated.VPNIsUp)
	if err != nil {
		return updated, err
	}
	return updated, nil
}

func (s Settings) copy() (copied Settings) {
	copied.VPNIsUp = gosettings.CopyPointer(s.VPNIsUp)
	copied.Service = s.Service.Copy()
	return copied
}

func (s *Settings) overrideWith(update Settings) {
	s.VPNIsUp = gosettings.OverrideWithPointer(s.VPNIsUp, update.VPNIsUp)
	s.Service.OverrideWith(update.Service)
}

func (s Settings) validate(forStartup bool) (err error) {
	return s.Service.Validate(forStartup)
}
