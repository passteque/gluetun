package settings

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/openvpn/extract"
	"github.com/qdm12/gluetun/internal/provider/privateinternetaccess/presets"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// OpenVPN contains settings to configure the OpenVPN client.
type OpenVPN struct {
	// Version is the OpenVPN version to run.
	// It can only be "2.5" or "2.6".
	Version string `json:"version"`
	// User is the OpenVPN authentication username.
	// It cannot be nil in the internal state if OpenVPN is used.
	// It is usually required but in some cases can be the empty string
	// to indicate no user+password authentication is needed.
	User *string `json:"user"`
	// Password is the OpenVPN authentication password.
	// It cannot be nil in the internal state if OpenVPN is used.
	// It is usually required but in some cases can be the empty string
	// to indicate no user+password authentication is needed.
	Password *string `json:"password"`
	// ConfFile is a custom OpenVPN configuration file path.
	// It can be set to the empty string for it to be ignored.
	// It cannot be nil in the internal state.
	ConfFile *string `json:"config_file_path"`
	// Ciphers is a list of ciphers to use for OpenVPN,
	// different from the ones specified by the VPN
	// service provider configuration files.
	Ciphers []string `json:"ciphers"`
	// Auth is an auth algorithm to use in OpenVPN instead
	// of the one specified by the VPN service provider.
	// It cannot be nil in the internal state.
	// It is ignored if it is set to the empty string.
	Auth *string `json:"auth"`
	// Cert is the base64 encoded DER of an OpenVPN certificate for the <cert> block.
	// This is notably used by Cyberghost and VPN secure.
	// It can be set to the empty string to be ignored.
	// It cannot be nil in the internal state.
	Cert *string `json:"cert"`
	// Key is the base64 encoded DER of an OpenVPN key.
	// This is used by Cyberghost and VPN Unlimited.
	// It can be set to the empty string to be ignored.
	// It cannot be nil in the internal state.
	Key *string `json:"key"`
	// EncryptedKey is the base64 encoded DER of an encrypted key for OpenVPN.
	// It is used by VPN secure.
	// It defaults to the empty string meaning it is not
	// to be used. KeyPassphrase must be set if this one is set.
	EncryptedKey *string `json:"encrypted_key"`
	// KeyPassphrase is the key passphrase to be used by OpenVPN
	// to decrypt the EncryptedPrivateKey. It defaults to the
	// empty string and must be set if EncryptedPrivateKey is set.
	KeyPassphrase *string `json:"key_passphrase"`
	// PIAEncPreset is the encryption preset for
	// Private Internet Access. It can be set to an
	// empty string for other providers.
	PIAEncPreset *string `json:"pia_encryption_preset"`
	// MSSFix is the value (1 to 10000) to set for the
	// mssfix option for OpenVPN. It is ignored if set to 0.
	// It cannot be nil in the internal state.
	MSSFix *uint16 `json:"mssfix"`
	// Interface is the OpenVPN device interface name.
	// It cannot be an empty string in the internal state.
	Interface string `json:"interface"`
	// ProcessUser is the OpenVPN process OS username
	// to use. It cannot be empty in the internal state.
	// It defaults to 'root'.
	ProcessUser string `json:"process_user"`
	// Verbosity is the OpenVPN verbosity level from 0 to 6.
	// It cannot be nil in the internal state.
	Verbosity *int `json:"verbosity"`
	// Flags is a slice of additional flags to be passed
	// to the OpenVPN program.
	Flags []string `json:"flags"`
}

var ivpnAccountID = regexp.MustCompile(`^(i|ivpn)\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}$`)

func (o OpenVPN) validate(vpnProvider string) (err error) {
	// Validate version
	validVersions := []string{openvpn.Openvpn25, openvpn.Openvpn26}
	if err = validate.IsOneOf(o.Version, validVersions...); err != nil {
		return fmt.Errorf("version is not valid: %w", err)
	}

	isCustom := vpnProvider == providers.Custom
	isUserRequired := !isCustom &&
		vpnProvider != providers.Airvpn &&
		vpnProvider != providers.VPNSecure

	if isUserRequired && *o.User == "" {
		return errors.New("user is empty")
	}

	passwordRequired := isUserRequired &&
		(vpnProvider != providers.Ivpn || !ivpnAccountID.MatchString(*o.User))

	if passwordRequired && *o.Password == "" {
		return errors.New("password is empty")
	}

	err = validateOpenVPNConfigFilepath(isCustom, *o.ConfFile)
	if err != nil {
		return fmt.Errorf("custom configuration file: %w", err)
	}

	err = validateOpenVPNClientCertificate(vpnProvider, *o.Cert)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}

	err = validateOpenVPNClientKey(vpnProvider, *o.Key)
	if err != nil {
		return fmt.Errorf("client key: %w", err)
	}

	err = validateOpenVPNEncryptedKey(vpnProvider, *o.EncryptedKey)
	if err != nil {
		return fmt.Errorf("encrypted key: %w", err)
	}

	if *o.EncryptedKey != "" && *o.KeyPassphrase == "" {
		return errors.New("key passphrase is empty")
	}

	const maxMSSFix = 10000
	if *o.MSSFix > maxMSSFix {
		return fmt.Errorf("mssfix option value is too high: %d is over the maximum value of %d", *o.MSSFix, maxMSSFix)
	}

	if !regexpInterfaceName.MatchString(o.Interface) {
		return fmt.Errorf("interface name is not valid: '%s' does not match regex '%s'", o.Interface, regexpInterfaceName)
	}

	if *o.Verbosity < 0 || *o.Verbosity > 6 {
		return fmt.Errorf("verbosity value is out of bounds: %d can only be between 0 and 5", o.Verbosity)
	}

	return nil
}

func validateOpenVPNConfigFilepath(isCustom bool,
	confFile string,
) (err error) {
	if !isCustom {
		return nil
	}

	if confFile == "" {
		return errors.New("filepath is missing")
	}

	err = validate.FileExists(confFile)
	if err != nil {
		return err
	}

	extractor := extract.New()
	_, _, err = extractor.Data(confFile)
	if err != nil {
		return fmt.Errorf("extracting information from custom configuration file: %w", err)
	}

	return nil
}

func validateOpenVPNClientCertificate(vpnProvider,
	clientCert string,
) (err error) {
	switch vpnProvider {
	case
		providers.Airvpn,
		providers.Cyberghost,
		providers.VPNSecure,
		providers.VPNUnlimited:
		if clientCert == "" {
			return errors.New("missing value")
		}
	}

	if clientCert == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(clientCert)
	if err != nil {
		return err
	}
	return nil
}

func validateOpenVPNClientKey(vpnProvider, clientKey string) (err error) {
	switch vpnProvider {
	case
		providers.Airvpn,
		providers.Cyberghost,
		providers.VPNUnlimited:
		if clientKey == "" {
			return errors.New("missing value")
		}
	}

	if clientKey == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(clientKey)
	if err != nil {
		return err
	}
	return nil
}

func validateOpenVPNEncryptedKey(vpnProvider,
	encryptedPrivateKey string,
) (err error) {
	if vpnProvider == providers.VPNSecure && encryptedPrivateKey == "" {
		return errors.New("missing value")
	}

	if encryptedPrivateKey == "" {
		return nil
	}

	_, err = base64.StdEncoding.DecodeString(encryptedPrivateKey)
	if err != nil {
		return err
	}
	return nil
}

func (o *OpenVPN) copy() (copied OpenVPN) {
	return OpenVPN{
		Version:       o.Version,
		User:          gosettings.CopyPointer(o.User),
		Password:      gosettings.CopyPointer(o.Password),
		ConfFile:      gosettings.CopyPointer(o.ConfFile),
		Ciphers:       gosettings.CopySlice(o.Ciphers),
		Auth:          gosettings.CopyPointer(o.Auth),
		Cert:          gosettings.CopyPointer(o.Cert),
		Key:           gosettings.CopyPointer(o.Key),
		EncryptedKey:  gosettings.CopyPointer(o.EncryptedKey),
		KeyPassphrase: gosettings.CopyPointer(o.KeyPassphrase),
		PIAEncPreset:  gosettings.CopyPointer(o.PIAEncPreset),
		MSSFix:        gosettings.CopyPointer(o.MSSFix),
		Interface:     o.Interface,
		ProcessUser:   o.ProcessUser,
		Verbosity:     gosettings.CopyPointer(o.Verbosity),
		Flags:         gosettings.CopySlice(o.Flags),
	}
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (o *OpenVPN) overrideWith(other OpenVPN) {
	o.Version = gosettings.OverrideWithComparable(o.Version, other.Version)
	o.User = gosettings.OverrideWithPointer(o.User, other.User)
	o.Password = gosettings.OverrideWithPointer(o.Password, other.Password)
	o.ConfFile = gosettings.OverrideWithPointer(o.ConfFile, other.ConfFile)
	o.Ciphers = gosettings.OverrideWithSlice(o.Ciphers, other.Ciphers)
	o.Auth = gosettings.OverrideWithPointer(o.Auth, other.Auth)
	o.Cert = gosettings.OverrideWithPointer(o.Cert, other.Cert)
	o.Key = gosettings.OverrideWithPointer(o.Key, other.Key)
	o.EncryptedKey = gosettings.OverrideWithPointer(o.EncryptedKey, other.EncryptedKey)
	o.KeyPassphrase = gosettings.OverrideWithPointer(o.KeyPassphrase, other.KeyPassphrase)
	o.PIAEncPreset = gosettings.OverrideWithPointer(o.PIAEncPreset, other.PIAEncPreset)
	o.MSSFix = gosettings.OverrideWithPointer(o.MSSFix, other.MSSFix)
	o.Interface = gosettings.OverrideWithComparable(o.Interface, other.Interface)
	o.ProcessUser = gosettings.OverrideWithComparable(o.ProcessUser, other.ProcessUser)
	o.Verbosity = gosettings.OverrideWithPointer(o.Verbosity, other.Verbosity)
	o.Flags = gosettings.OverrideWithSlice(o.Flags, other.Flags)
}

func (o *OpenVPN) setDefaults(vpnProvider string) {
	o.Version = gosettings.DefaultComparable(o.Version, openvpn.Openvpn26)
	o.User = gosettings.DefaultPointer(o.User, "")
	if vpnProvider == providers.Mullvad {
		o.Password = gosettings.DefaultPointer(o.Password, "m")
	} else {
		o.Password = gosettings.DefaultPointer(o.Password, "")
	}

	o.ConfFile = gosettings.DefaultPointer(o.ConfFile, "")
	o.Auth = gosettings.DefaultPointer(o.Auth, "")
	o.Cert = gosettings.DefaultPointer(o.Cert, "")
	o.Key = gosettings.DefaultPointer(o.Key, "")
	o.EncryptedKey = gosettings.DefaultPointer(o.EncryptedKey, "")
	o.KeyPassphrase = gosettings.DefaultPointer(o.KeyPassphrase, "")

	var defaultEncPreset string
	if vpnProvider == providers.PrivateInternetAccess {
		defaultEncPreset = presets.Strong
	}
	o.PIAEncPreset = gosettings.DefaultPointer(o.PIAEncPreset, defaultEncPreset)
	o.MSSFix = gosettings.DefaultPointer(o.MSSFix, 0)
	o.Interface = gosettings.DefaultComparable(o.Interface, "tun0")
	o.ProcessUser = gosettings.DefaultComparable(o.ProcessUser, "root")
	o.Verbosity = gosettings.DefaultPointer(o.Verbosity, 1)
}

func (o OpenVPN) String() string {
	return o.toLinesNode().String()
}

func (o OpenVPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("OpenVPN settings:")
	node.Appendf("OpenVPN version: %s", o.Version)
	node.Appendf("User: %s", gosettings.ObfuscateKey(*o.User))
	node.Appendf("Password: %s", gosettings.ObfuscateKey(*o.Password))

	if *o.ConfFile != "" {
		node.Appendf("Custom configuration file: %s", *o.ConfFile)
	}

	if len(o.Ciphers) > 0 {
		node.Appendf("Ciphers: %s", o.Ciphers)
	}

	if *o.Auth != "" {
		node.Appendf("Auth: %s", *o.Auth)
	}

	if *o.Cert != "" {
		node.Appendf("Client crt: %s", gosettings.ObfuscateKey(*o.Cert))
	}

	if *o.Key != "" {
		node.Appendf("Client key: %s", gosettings.ObfuscateKey(*o.Key))
	}

	if *o.EncryptedKey != "" {
		node.Appendf("Encrypted key: %s (key passhrapse %s)",
			gosettings.ObfuscateKey(*o.EncryptedKey), gosettings.ObfuscateKey(*o.KeyPassphrase))
	}

	if *o.PIAEncPreset != "" {
		node.Appendf("Private Internet Access encryption preset: %s", *o.PIAEncPreset)
	}

	if *o.MSSFix > 0 {
		node.Appendf("MSS Fix: %d", *o.MSSFix)
	}

	if o.Interface != "" {
		node.Appendf("Network interface: %s", o.Interface)
	}

	node.Appendf("Run OpenVPN as: %s", o.ProcessUser)

	node.Appendf("Verbosity level: %d", *o.Verbosity)

	if len(o.Flags) > 0 {
		node.Appendf("Flags: %s", o.Flags)
	}

	return node
}

// WithDefaults is a shorthand using setDefaults.
// It's used in unit tests in other packages.
func (o OpenVPN) WithDefaults(provider string) OpenVPN {
	o.setDefaults(provider)
	return o
}

func (o *OpenVPN) read(r *reader.Reader) (err error) {
	o.Version = r.String("OPENVPN_VERSION")
	o.User = r.Get("OPENVPN_USER", reader.RetroKeys("USER"), reader.ForceLowercase(false))
	o.Password = r.Get("OPENVPN_PASSWORD", reader.RetroKeys("PASSWORD"), reader.ForceLowercase(false))
	o.ConfFile = r.Get("OPENVPN_CUSTOM_CONFIG", reader.ForceLowercase(false))
	o.Ciphers = r.CSV("OPENVPN_CIPHERS", reader.RetroKeys("OPENVPN_CIPHER"))
	o.Auth = r.Get("OPENVPN_AUTH")
	o.Cert = r.Get("OPENVPN_CERT", reader.ForceLowercase(false))
	o.Key = r.Get("OPENVPN_KEY", reader.ForceLowercase(false))
	o.EncryptedKey = r.Get("OPENVPN_ENCRYPTED_KEY", reader.ForceLowercase(false))
	o.KeyPassphrase = r.Get("OPENVPN_KEY_PASSPHRASE", reader.ForceLowercase(false))
	o.PIAEncPreset = r.Get("PRIVATE_INTERNET_ACCESS_OPENVPN_ENCRYPTION_PRESET",
		reader.RetroKeys("ENCRYPTION", "PIA_ENCRYPTION"))

	o.MSSFix, err = r.Uint16Ptr("OPENVPN_MSSFIX")
	if err != nil {
		return err
	}

	o.Interface = r.String("VPN_INTERFACE",
		reader.RetroKeys("OPENVPN_INTERFACE"), reader.ForceLowercase(false))

	o.ProcessUser, err = readOpenVPNProcessUser(r)
	if err != nil {
		return err
	}

	o.Verbosity, err = r.IntPtr("OPENVPN_VERBOSITY")
	if err != nil {
		return err
	}

	flagsPtr := r.Get("OPENVPN_FLAGS", reader.ForceLowercase(false))
	if flagsPtr != nil {
		o.Flags = strings.Fields(*flagsPtr)
	}

	return nil
}

func readOpenVPNProcessUser(r *reader.Reader) (processUser string, err error) {
	value, err := r.BoolPtr("OPENVPN_ROOT") // Retro-compatibility
	if err != nil {
		return "", err
	} else if value != nil {
		if *value {
			return "root", nil
		}
		const defaultNonRootUser = "nonrootuser"
		return defaultNonRootUser, nil
	}

	return r.String("OPENVPN_PROCESS_USER"), nil
}
