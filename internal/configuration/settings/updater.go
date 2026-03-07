package settings

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Updater contains settings to configure the VPN
// server information updater.
type Updater struct {
	// Period is the period for which the updater
	// should run. It can be set to 0 to disable the
	// updater. It cannot be nil in the internal state.
	// TODO change to value and add Enabled field.
	Period *time.Duration
	// MinRatio is the minimum ratio of servers to
	// find per provider, compared to the total current
	// number of servers. It defaults to 0.8.
	MinRatio float64
	// Providers is the list of VPN service providers
	// to update server information for.
	Providers []string
	// ProtonEmail is the email to authenticate with the Proton API.
	ProtonEmail *string
	// ProtonPassword is the password to authenticate with the Proton API.
	ProtonPassword *string
}

func (u Updater) Validate() (err error) {
	const minPeriod = time.Minute
	if *u.Period > 0 && *u.Period < minPeriod {
		return fmt.Errorf("%w: %d must be larger than %s",
			ErrUpdaterPeriodTooSmall, *u.Period, minPeriod)
	}

	if u.MinRatio <= 0 || u.MinRatio > 1 {
		return fmt.Errorf("%w: %.2f must be between 0+ and 1",
			ErrMinRatioNotValid, u.MinRatio)
	}

	validProviders := providers.All()
	for _, provider := range u.Providers {
		err = validate.IsOneOf(provider, validProviders...)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrVPNProviderNameNotValid, err)
		}

		if provider == providers.Protonvpn {
			authenticatedAPI := *u.ProtonEmail != "" || *u.ProtonPassword != ""
			if authenticatedAPI {
				switch {
				case *u.ProtonEmail == "":
					return fmt.Errorf("%w", ErrUpdaterProtonEmailMissing)
				case *u.ProtonPassword == "":
					return fmt.Errorf("%w", ErrUpdaterProtonPasswordMissing)
				}
			}
		}
	}

	return nil
}

func (u *Updater) copy() (copied Updater) {
	return Updater{
		Period:         gosettings.CopyPointer(u.Period),
		MinRatio:       u.MinRatio,
		Providers:      gosettings.CopySlice(u.Providers),
		ProtonEmail:    gosettings.CopyPointer(u.ProtonEmail),
		ProtonPassword: gosettings.CopyPointer(u.ProtonPassword),
	}
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (u *Updater) overrideWith(other Updater) {
	u.Period = gosettings.OverrideWithPointer(u.Period, other.Period)
	u.MinRatio = gosettings.OverrideWithComparable(u.MinRatio, other.MinRatio)
	u.Providers = gosettings.OverrideWithSlice(u.Providers, other.Providers)
	u.ProtonEmail = gosettings.OverrideWithPointer(u.ProtonEmail, other.ProtonEmail)
	u.ProtonPassword = gosettings.OverrideWithPointer(u.ProtonPassword, other.ProtonPassword)
}

func (u *Updater) SetDefaults(vpnProvider string) {
	u.Period = gosettings.DefaultPointer(u.Period, 0)

	if u.MinRatio == 0 {
		const defaultMinRatio = 0.8
		u.MinRatio = defaultMinRatio
	}

	if len(u.Providers) == 0 && vpnProvider != providers.Custom {
		u.Providers = []string{vpnProvider}
	}

	// Set these to empty strings to avoid nil pointer panics
	u.ProtonEmail = gosettings.DefaultPointer(u.ProtonEmail, "")
	u.ProtonPassword = gosettings.DefaultPointer(u.ProtonPassword, "")
}

func (u Updater) String() string {
	return u.toLinesNode().String()
}

func (u Updater) toLinesNode() (node *gotree.Node) {
	if *u.Period == 0 || len(u.Providers) == 0 {
		return nil
	}

	node = gotree.New("Server data updater settings:")
	node.Appendf("Update period: %s", *u.Period)
	node.Appendf("Minimum ratio: %.1f", u.MinRatio)
	node.Appendf("Providers to update: %s", strings.Join(u.Providers, ", "))
	if slices.Contains(u.Providers, providers.Protonvpn) {
		node.Appendf("Proton API email: %s", *u.ProtonEmail)
		node.Appendf("Proton API password: %s", gosettings.ObfuscateKey(*u.ProtonPassword))
	}

	return node
}

func (u *Updater) read(r *reader.Reader) (err error) {
	u.Period, err = r.DurationPtr("UPDATER_PERIOD")
	if err != nil {
		return err
	}

	u.MinRatio, err = r.Float64("UPDATER_MIN_RATIO")
	if err != nil {
		return err
	}

	u.Providers = r.CSV("UPDATER_VPN_SERVICE_PROVIDERS")

	u.ProtonEmail = r.Get("UPDATER_PROTONVPN_EMAIL")
	if u.ProtonEmail == nil {
		protonUsername := r.String("UPDATER_PROTONVPN_USERNAME", reader.IsRetro("UPDATER_PROTONVPN_EMAIL"))
		if protonUsername != "" {
			protonEmail := protonUsername + "@protonmail.com"
			u.ProtonEmail = &protonEmail
		}
	}
	u.ProtonPassword = r.Get("UPDATER_PROTONVPN_PASSWORD")

	return nil
}
