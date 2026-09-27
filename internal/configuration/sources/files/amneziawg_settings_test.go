package files

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (noopWarner) Warn(string) {}

func Test_Source_Read_amneziaWGSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		flags        string
		enabled      bool
		upstreamType string
	}{
		"on":             {flags: "on", enabled: true},
		"off":            {flags: "off"},
		"numeric_true":   {flags: "1", enabled: true},
		"numeric_false":  {flags: "0"},
		"explicit_plain": {flags: "1", enabled: true, upstreamType: settings.DNSUpstreamTypePlain},
		"explicit_dot":   {flags: "1", enabled: true, upstreamType: settings.DNSUpstreamTypeDot},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rootDirectory := t.TempDir()
			configDirectory := filepath.Join(rootDirectory, "amneziawg")
			err := os.Mkdir(configDirectory, 0o700)
			require.NoError(t, err)
			const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
			const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="
			const presharedKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM="
			const protectionKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ="
			config := fmt.Sprintf(`[Interface]
PrivateKey = `+privateKey+`
Address = 10.0.0.2/32
DNS = 9.9.9.9, 149.112.112.112
Jc = 4
Jmin = 20
Jmax = 60
S1 = 64
S2 = 65
S3 = 66
S4 = 67
H1 = 101-109
H2 = 201-209
H3 = 301-309
H4 = 401-409
I1 = <b 0x1234>
I2 = <r 8>
I3 = <rd 8>
I4 = <rc 8>
I5 = <t>
HeaderProtectionKey = `+protectionKey+`
ContentPaddingAddition = 64-128
RekeyAfterTime = 110-126
RekeyTimeout = 5
RejectAfterTime = 170-182
KeepaliveTimeout = 12-17
MaxHandshakeAttempts = 3
RandomTrailers = %[1]s
DisableCookies = %[1]s

[Peer]
PublicKey = `+publicKey+`
PresharedKey = `+presharedKey+`
Endpoint = 198.51.100.2:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25-35
`, testCase.flags)
			err = os.WriteFile(filepath.Join(configDirectory, "awg0.conf"), []byte(config), 0o600)
			require.NoError(t, err)
			source := &Source{rootDirectory: rootDirectory, environ: map[string]string{}, warner: noopWarner{}}
			settingsReader := reader.New(reader.Settings{Sources: []reader.Source{
				source,
				env.New(env.Settings{Environ: []string{
					"VPN_TYPE=amneziawg", "VPN_SERVICE_PROVIDER=custom",
					"AMNEZIAWG_RANDOM_TRAILERS=off", "AMNEZIAWG_DISABLE_COOKIES=off",
					"AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL=0",
					"AMNEZIAWG_ALLOWED_IPS=10.0.0.0/8",
					"DNS_UPSTREAM_RESOLVER_TYPE=" + testCase.upstreamType,
				}}),
			}})
			configuration := settings.Settings{}
			err = configuration.Read(settingsReader, noopWarner{})
			require.NoError(t, err)
			configuration.SetDefaults()

			amneziaWG := configuration.VPN.AmneziaWg
			assert.Equal(t, privateKey, *amneziaWG.Wireguard.PrivateKey)
			assert.Equal(t, presharedKey, *amneziaWG.Wireguard.PreSharedKey)
			selection := configuration.VPN.Provider.ServerSelection.Wireguard
			assert.Equal(t, publicKey, selection.PublicKey)
			assert.Equal(t, netip.MustParseAddr("198.51.100.2"), selection.EndpointIP)
			assert.Equal(t, uint16(51820), *selection.EndpointPort)
			assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, amneziaWG.Wireguard.Addresses)
			assert.Equal(t, []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
			}, amneziaWG.Wireguard.AllowedIPs)
			assert.Equal(t, uint16(4), *amneziaWG.JunkPacketCount)
			assert.Equal(t, uint16(20), *amneziaWG.JunkPacketMin)
			assert.Equal(t, uint16(60), *amneziaWG.JunkPacketMax)
			assert.Equal(t, [4]uint16{64, 65, 66, 67}, [4]uint16{
				*amneziaWG.PaddingS1, *amneziaWG.PaddingS2, *amneziaWG.PaddingS3, *amneziaWG.PaddingS4,
			})
			assert.Equal(t, [4]string{"101-109", "201-209", "301-309", "401-409"}, [4]string{
				*amneziaWG.HeaderH1, *amneziaWG.HeaderH2, *amneziaWG.HeaderH3, *amneziaWG.HeaderH4,
			})
			assert.Equal(t, [5]string{"<b 0x1234>", "<r 8>", "<rd 8>", "<rc 8>", "<t>"}, [5]string{
				*amneziaWG.InitPacketI1, *amneziaWG.InitPacketI2, *amneziaWG.InitPacketI3,
				*amneziaWG.InitPacketI4, *amneziaWG.InitPacketI5,
			})
			assert.Equal(t, protectionKey, *amneziaWG.HeaderProtectionKey)
			assert.Equal(t, [2]uint32{64, 128}, *amneziaWG.ContentPaddingAddition)
			assert.Equal(t, [2]uint32{110, 126}, *amneziaWG.RekeyAfterTime)
			assert.Equal(t, [2]uint32{5, 5}, *amneziaWG.RekeyTimeout)
			assert.Equal(t, [2]uint32{170, 182}, *amneziaWG.RejectAfterTime)
			assert.Equal(t, [2]uint32{12, 17}, *amneziaWG.KeepaliveTimeout)
			assert.Equal(t, [2]uint32{3, 3}, *amneziaWG.MaxHandshakeAttempts)
			assert.Equal(t, [2]uint32{25, 35}, *amneziaWG.PersistentKeepaliveInterval)
			assert.Zero(t, *amneziaWG.Wireguard.PersistentKeepaliveInterval)
			assert.Equal(t, testCase.enabled, *amneziaWG.RandomTrailers)
			assert.Equal(t, testCase.enabled, *amneziaWG.DisableCookies)
			if testCase.upstreamType == settings.DNSUpstreamTypeDot {
				assert.Equal(t, settings.DNSUpstreamTypeDot, configuration.DNS.UpstreamType)
				assert.Empty(t, configuration.DNS.UpstreamPlainAddresses)
				return
			}
			assert.Equal(t, settings.DNSUpstreamTypePlain, configuration.DNS.UpstreamType)
			assert.Equal(t, []netip.AddrPort{
				netip.MustParseAddrPort("9.9.9.9:53"), netip.MustParseAddrPort("149.112.112.112:53"),
			}, configuration.DNS.UpstreamPlainAddresses)
		})
	}
}
