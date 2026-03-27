package utils

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/openvpn/pkcs8"
)

type OpenVPNProviderSettings struct {
	Ping          int
	RemoteCertTLS bool
	Ciphers       []string
	Auth          string
	CAs           []string
	CRLVerify     string
	Cert          string
	Key           string
	RSAKey        string
	TLSAuth       string
	TLSCrypt      string
	MssFix        uint16
	FastIO        bool
	AuthUserPass  bool
	AuthToken     bool
	Fragment      uint16
	SndBuf        uint32
	RcvBuf        uint32
	// VerifyX509Name can be set to a custom name to verify against.
	// Note VerifyX509Type has to be set for it to be verified.
	// If it is left unset, the code will deduce a name to verify against
	// using the connection hostname and according to VerifyX509Type.
	VerifyX509Name string
	// VerifyX509Type can be "name-prefix", "name"
	VerifyX509Type string
	TLSCipher      string
	TunMTU         uint16
	TunMTUExtra    uint16
	RenegDisabled  bool
	RenegSec       uint16
	KeyDirection   string
	SetEnv         map[string]string
	ExtraLines     []string
	UDPLines       []string
	IPv6Lines      []string
}

//nolint:gocognit,gocyclo
func OpenVPNConfig(provider OpenVPNProviderSettings,
	connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) []string {
	var lines openvpnConfigLines
	lines.add("client")
	lines.add("nobind")
	lines.add("tls-exit")                 // exit OpenVPN on a TLS error
	lines.add("auth-nocache")             // do not cache auth credentials
	lines.add("mute-replay-warnings")     // these are often ignored by some VPN providers
	lines.add("auth-retry", "nointeract") // retry authenticating without interaction
	lines.add("suppress-timestamps")      // do not log timestamps, the Gluetun logger takes care of it
	lines.add("dev", settings.Interface)
	lines.add("verb", fmt.Sprint(*settings.Verbosity))
	lines.add("proto", connection.Protocol)
	lines.add("remote", connection.IP.String(), fmt.Sprint(connection.Port))

	if *settings.User != "" {
		lines.add("auth-user-pass", openvpn.AuthConf)
	}

	if !provider.AuthToken {
		lines.add("pull-filter", "ignore", `"auth-token"`) // prevent auth failed loops
	}

	if provider.KeyDirection != "" {
		lines.add("key-direction", provider.KeyDirection)
	}

	if provider.Ping > 0 {
		lines.add("ping", fmt.Sprint(provider.Ping))
	}

	if provider.RenegDisabled {
		lines.add("reneg-sec", "0")
	} else if provider.RenegSec > 0 {
		lines.add("reneg-sec", fmt.Sprint(provider.RenegSec))
	}

	if provider.RemoteCertTLS {
		// equivalent to older 'ns-cert-type' option
		lines.add("remote-cert-tls server")
	}

	x509Type := provider.VerifyX509Type
	if x509Type != "" {
		x509Name := provider.VerifyX509Name
		if x509Name == "" {
			// find name from connection hostname depending on type
			switch x509Type {
			case "name":
				x509Name = connection.Hostname
			case "name-prefix":
				x509Name = strings.Split(connection.Hostname, ".")[0]
			default:
				panic(fmt.Sprintf("verify-x509-name type not supported: %q", x509Type))
			}
		}
		lines.add("verify-x509-name", x509Name, x509Type)
	}

	if provider.TLSCipher != "" {
		lines.add("tls-cipher", provider.TLSCipher)
	}

	if provider.FastIO {
		lines.add("fast-io")
	}

	ciphers := defaultStringSlice(settings.Ciphers, provider.Ciphers)
	cipherLines := CipherLines(ciphers)
	lines.addLines(cipherLines)

	auth := defaultString(*settings.Auth, provider.Auth)
	if auth != "" {
		lines.add("auth", auth)
	}

	if provider.TunMTU > 0 {
		lines.add("tun-mtu", fmt.Sprint(provider.TunMTU))
	}

	if provider.TunMTUExtra > 0 {
		lines.add("tun-mtu-extra", fmt.Sprint(provider.TunMTUExtra))
	}

	mssFix := defaultUint16(*settings.MSSFix, provider.MssFix)
	if mssFix > 0 {
		lines.add("mssfix", fmt.Sprint(mssFix))
	}

	if provider.Fragment > 0 {
		lines.add("fragment", fmt.Sprint(provider.Fragment))
	}

	if provider.SndBuf > 0 {
		lines.add("sndbuf", fmt.Sprint(provider.SndBuf))
	}

	if provider.RcvBuf > 0 {
		lines.add("rcvbuf", fmt.Sprint(provider.RcvBuf))
	}

	if connection.Protocol == constants.UDP {
		lines.add("explicit-exit-notify")
		lines.addLines(provider.UDPLines)
	}

	if settings.ProcessUser != "root" {
		lines.add("user", settings.ProcessUser)
		lines.add("persist-tun")
		lines.add("persist-key")
	}

	if !ipv6Supported {
		lines.add("pull-filter", "ignore", `"tun-ipv6"`)
		lines.add("pull-filter", "ignore", `"route-ipv6"`)
		lines.add("pull-filter", "ignore", `"ifconfig-ipv6"`)
		lines.addLines(provider.IPv6Lines)
	}

	for envKey, envValue := range provider.SetEnv {
		lines.add("setenv", envKey, envValue)
	}

	if len(provider.CAs) > 0 {
		lines.addLines(WrapOpenvpnCAs(provider.CAs))
	}
	if provider.CRLVerify != "" {
		lines.addLines(WrapOpenvpnCRLVerify(provider.CRLVerify))
	}
	if provider.Cert != "" {
		lines.addLines(WrapOpenvpnCert(provider.Cert))
	}
	if provider.Key != "" {
		lines.addLines(WrapOpenvpnKey(provider.Key))
	}
	if provider.RSAKey != "" {
		lines.addLines(WrapOpenvpnRSAKey(provider.RSAKey))
	}
	if provider.TLSAuth != "" {
		lines.addLines(WrapOpenvpnTLSAuth(provider.TLSAuth))
	}
	if provider.TLSCrypt != "" {
		lines.addLines(WrapOpenvpnTLSCrypt(provider.TLSCrypt))
	}

	if *settings.EncryptedKey != "" {
		encryptedBase64DERKey := *settings.EncryptedKey
		// OpenVPN above 2.4 does not support old encryption schemes such as
		// DES-CBC, so decrypt and reencrypt the key.
		// This is a workaround for VPN secure.
		var err error
		encryptedBase64DERKey, err = pkcs8.UpgradeEncryptedKey(encryptedBase64DERKey, *settings.KeyPassphrase)
		if err != nil {
			// TODO return an error instead.
			panic(fmt.Sprintf("upgrading encrypted key: %s", err))
		}
		lines.add("askpass", openvpn.AskPassPath)
		lines.addLines(WrapOpenvpnEncryptedKey(encryptedBase64DERKey))
	}

	if *settings.Cert != "" {
		lines.addLines(WrapOpenvpnCert(*settings.Cert))
	}

	if *settings.Key != "" {
		lines.addLines(WrapOpenvpnKey(*settings.Key))
	}

	lines.addLines(provider.ExtraLines)

	// Add a trailing empty line
	lines.add("")

	return lines
}

type openvpnConfigLines []string

func (o *openvpnConfigLines) add(words ...string) {
	*o = append(*o, strings.Join(words, " "))
}

func (o *openvpnConfigLines) addLines(lines []string) {
	for _, line := range lines {
		o.add(line)
	}
}

func defaultString(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func defaultUint16(value, defaultValue uint16) uint16 {
	if value == 0 {
		return defaultValue
	}
	return value
}

func defaultStringSlice(value, defaultValue []string) (
	result []string,
) {
	if len(value) > 0 {
		result = make([]string, len(value))
		copy(result, value)
		return result
	}
	result = make([]string, len(defaultValue))
	copy(result, defaultValue)
	return result
}

func WrapOpenvpnCA(certificate string) (lines []string) {
	return WrapOpenvpnCAs([]string{certificate})
}

func WrapOpenvpnCAs(certificates []string) (lines []string) {
	lines = append(lines, "<ca>")
	for _, certificate := range certificates {
		lines = append(lines,
			"-----BEGIN CERTIFICATE-----",
			certificate,
			"-----END CERTIFICATE-----",
		)
	}
	lines = append(lines, "</ca>")
	return lines
}

func WrapOpenvpnCert(clientCertificate string) (lines []string) {
	return []string{
		"<cert>",
		"-----BEGIN CERTIFICATE-----",
		clientCertificate,
		"-----END CERTIFICATE-----",
		"</cert>",
	}
}

func WrapOpenvpnCRLVerify(x509CRL string) (lines []string) {
	return []string{
		"<crl-verify>",
		"-----BEGIN X509 CRL-----",
		x509CRL,
		"-----END X509 CRL-----",
		"</crl-verify>",
	}
}

func WrapOpenvpnKey(clientKey string) (lines []string) {
	return []string{
		"<key>",
		"-----BEGIN PRIVATE KEY-----",
		clientKey,
		"-----END PRIVATE KEY-----",
		"</key>",
	}
}

func WrapOpenvpnEncryptedKey(encryptedKey string) (lines []string) {
	return []string{
		"<key>",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		encryptedKey,
		"-----END ENCRYPTED PRIVATE KEY-----",
		"</key>",
	}
}

func WrapOpenvpnRSAKey(rsaPrivateKey string) (lines []string) {
	return []string{
		"<key>",
		"-----BEGIN RSA PRIVATE KEY-----",
		rsaPrivateKey,
		"-----END RSA PRIVATE KEY-----",
		"</key>",
	}
}

func WrapOpenvpnTLSAuth(staticKeyV1 string) (lines []string) {
	return []string{
		"<tls-auth>",
		"-----BEGIN OpenVPN Static key V1-----",
		staticKeyV1,
		"-----END OpenVPN Static key V1-----",
		"</tls-auth>",
	}
}

func WrapOpenvpnTLSCrypt(staticKeyV1 string) (lines []string) {
	return []string{
		"<tls-crypt>",
		"-----BEGIN OpenVPN Static key V1-----",
		staticKeyV1,
		"-----END OpenVPN Static key V1-----",
		"</tls-crypt>",
	}
}
