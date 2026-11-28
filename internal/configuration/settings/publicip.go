package settings

import (
	"fmt"
	"path/filepath"

	"github.com/qdm12/gluetun/internal/publicip/api"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// PublicIP contains settings for port forwarding.
type PublicIP struct {
	// Enabled is set to true to fetch the public ip address
	// information on VPN connection. It defaults to true.
	Enabled *bool
	// IPFilepath is the public IP address status file path
	// to use. It can be the empty string to indicate not
	// to write to a file. It cannot be nil for the
	// internal state
	IPFilepath *string
	// APIs is the list of public ip APIs to use to fetch public IP information.
	// If there is more than one API, the first one is used
	// by default and the others are used as fallbacks in case of
	// the service rate limiting us. It defaults to use all services,
	// with the first one being ipinfo.io for historical reasons.
	APIs []PublicIPAPI
}

type PublicIPAPI struct {
	// Name is the name of the public ip API service.
	// It can be "cloudflare", "ifconfigco", "internetdata", "ip2location" or "ipinfo".
	Name string
	// Token is the token to use for the public ip API service.
	Token string
}

// UpdateWith deep copies the receiving settings, overrides the copy with
// fields set in the partialUpdate argument, validates the new settings
// and returns them if they are valid, or returns an error otherwise.
// In all cases, the receiving settings are unmodified.
func (p PublicIP) UpdateWith(partialUpdate PublicIP) (updatedSettings PublicIP, err error) {
	updatedSettings = p.copy()
	updatedSettings.overrideWith(partialUpdate)
	err = updatedSettings.validate()
	if err != nil {
		return updatedSettings, fmt.Errorf("validating updated settings: %w", err)
	}
	return updatedSettings, nil
}

func (p PublicIP) validate() (err error) {
	if *p.IPFilepath != "" { // optional
		_, err := filepath.Abs(*p.IPFilepath)
		if err != nil {
			return fmt.Errorf("filepath is not valid: %w", err)
		}
	}

	for _, publicIPAPI := range p.APIs {
		_, err = api.ParseProvider(publicIPAPI.Name)
		if err != nil {
			return fmt.Errorf("API name: %w", err)
		}
	}

	return nil
}

func (p *PublicIP) copy() (copied PublicIP) {
	return PublicIP{
		Enabled:    gosettings.CopyPointer(p.Enabled),
		IPFilepath: gosettings.CopyPointer(p.IPFilepath),
		APIs:       gosettings.CopySlice(p.APIs),
	}
}

func (p *PublicIP) overrideWith(other PublicIP) {
	p.Enabled = gosettings.OverrideWithPointer(p.Enabled, other.Enabled)
	p.IPFilepath = gosettings.OverrideWithPointer(p.IPFilepath, other.IPFilepath)
	p.APIs = gosettings.OverrideWithSlice(p.APIs, other.APIs)
}

func (p *PublicIP) setDefaults() {
	p.Enabled = gosettings.DefaultPointer(p.Enabled, true)
	p.IPFilepath = gosettings.DefaultPointer(p.IPFilepath, "/tmp/gluetun/ip")
	p.APIs = gosettings.DefaultSlice(p.APIs, []PublicIPAPI{
		{Name: string(api.IPInfo)},
		{Name: string(api.Cloudflare)},
		{Name: string(api.IfConfigCo)},
		{Name: string(api.IP2Location)},
	})
}

func (p PublicIP) String() string {
	return p.toLinesNode().String()
}

func (p PublicIP) toLinesNode() (node *gotree.Node) {
	if !*p.Enabled {
		return gotree.New("Public IP settings: disabled")
	}

	node = gotree.New("Public IP settings:")

	if *p.IPFilepath != "" {
		node.Appendf("IP file path: %s", *p.IPFilepath)
	}

	baseAPIString := "Public IP data base API: " + p.APIs[0].Name
	if p.APIs[0].Token != "" {
		baseAPIString += " (token " + gosettings.ObfuscateKey(p.APIs[0].Token) + ")"
	}
	node.Append(baseAPIString)
	if len(p.APIs) > 1 {
		backupAPIsNode := node.Append("Public IP data backup APIs:")
		for i := 1; i < len(p.APIs); i++ {
			message := p.APIs[i].Name
			if p.APIs[i].Token != "" {
				message += " (token " + gosettings.ObfuscateKey(p.APIs[i].Token) + ")"
			}
			backupAPIsNode.Append(message)
		}
	}

	return node
}

func (p *PublicIP) read(r *reader.Reader, warner Warner) (err error) {
	p.Enabled, err = readPublicIPEnabled(r, warner)
	if err != nil {
		return err
	}

	p.IPFilepath = r.Get("PUBLICIP_FILE",
		reader.ForceLowercase(false), reader.RetroKeys("IP_STATUS_FILE"))

	apiNames := r.CSV("PUBLICIP_API")
	if len(apiNames) > 0 {
		apiTokens := r.CSV("PUBLICIP_API_TOKEN")
		p.APIs = make([]PublicIPAPI, len(apiNames))
		for i := range apiNames {
			p.APIs[i].Name = apiNames[i]
			var token string
			if i < len(apiTokens) { // only set token if it exists
				token = apiTokens[i]
			}
			p.APIs[i].Token = token
		}
	}

	return nil
}

func readPublicIPEnabled(r *reader.Reader, warner Warner) (
	enabled *bool, err error,
) {
	periodPtr, err := r.DurationPtr("PUBLICIP_PERIOD") // Retro-compatibility
	if err != nil {
		return nil, err
	} else if periodPtr == nil {
		return r.BoolPtr("PUBLICIP_ENABLED")
	}

	if *periodPtr == 0 {
		warner.Warn("please replace PUBLICIP_PERIOD=0 with PUBLICIP_ENABLED=no")
		return ptrTo(false), nil
	}

	warner.Warn("PUBLICIP_PERIOD is no longer used. " +
		"It is assumed from its non-zero value you want PUBLICIP_ENABLED=yes. " +
		"Please migrate to use PUBLICIP_ENABLED only in the future.")
	return ptrTo(true), nil
}
