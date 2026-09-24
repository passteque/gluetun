package amneziawg

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	amneziadevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Settings struct {
	Wireguard                   wireguard.Settings
	JunkPacketCount             uint16
	JunkPacketMin               uint16
	JunkPacketMax               uint16
	PaddingS1                   uint16
	PaddingS2                   uint16
	PaddingS3                   uint16
	PaddingS4                   uint16
	HeaderH1                    string
	HeaderH2                    string
	HeaderH3                    string
	HeaderH4                    string
	InitPacketI1                string
	InitPacketI2                string
	InitPacketI3                string
	InitPacketI4                string
	InitPacketI5                string
	HeaderProtectionKey         string
	ContentPaddingAddition      string
	RekeyAfterTime              string
	RekeyTimeout                string
	RejectAfterTime             string
	KeepaliveTimeout            string
	MaxHandshakeAttempts        string
	PersistentKeepaliveInterval string
	RandomTrailers              bool
	DisableCookies              bool
}

func (s Settings) uapiConfig() (config string, err error) {
	uintFields := map[string]uint16{
		"jc":   s.JunkPacketCount,
		"jmin": s.JunkPacketMin,
		"jmax": s.JunkPacketMax,
		"s1":   s.PaddingS1,
		"s2":   s.PaddingS2,
		"s3":   s.PaddingS3,
		"s4":   s.PaddingS4,
	}
	stringFields := map[string]string{
		"h1":                       s.HeaderH1,
		"h2":                       s.HeaderH2,
		"h3":                       s.HeaderH3,
		"h4":                       s.HeaderH4,
		"i1":                       s.InitPacketI1,
		"i2":                       s.InitPacketI2,
		"i3":                       s.InitPacketI3,
		"i4":                       s.InitPacketI4,
		"i5":                       s.InitPacketI5,
		"content_padding_addition": s.ContentPaddingAddition,
		"rekey_after_time":         s.RekeyAfterTime,
		"rekey_timeout":            s.RekeyTimeout,
		"reject_after_time":        s.RejectAfterTime,
		"keepalive_timeout":        s.KeepaliveTimeout,
		"max_handshake_attempts":   s.MaxHandshakeAttempts,
	}
	const additionalFields = 5
	lines := make([]string, 0, len(uintFields)+len(stringFields)+additionalFields)

	for key, val := range uintFields {
		lines = append(lines, fmt.Sprintf("%s=%d", key, val))
	}

	for key, val := range stringFields {
		lines = append(lines, key+"="+val)
	}
	if s.HeaderProtectionKey != "" {
		headerProtectionKey, err := wgtypes.ParseKey(s.HeaderProtectionKey)
		if err != nil {
			return "", fmt.Errorf("parsing header protection key: %w", err)
		}
		lines = append(lines, "header_protection_key="+hex.EncodeToString(headerProtectionKey[:]))
	}
	lines = append(lines, "random_trailers="+strconv.FormatBool(s.RandomTrailers))
	lines = append(lines, "disable_cookies="+strconv.FormatBool(s.DisableCookies))

	publicKey, err := wgtypes.ParseKey(s.Wireguard.PublicKey)
	if err != nil {
		return "", fmt.Errorf("parsing public key: %w", err)
	}
	lines = append(lines, "public_key="+hex.EncodeToString(publicKey[:]))
	persistentKeepaliveInterval, err := normalizePersistentKeepalive(s.PersistentKeepaliveInterval)
	if err != nil {
		return "", fmt.Errorf("normalizing persistent keepalive interval: %w", err)
	}
	lines = append(lines, "persistent_keepalive_interval="+persistentKeepaliveInterval)

	return strings.Join(lines, "\n"), nil
}

func (s *Settings) SetDefaults() {
	s.Wireguard.SetDefaults()
	if s.ContentPaddingAddition == "" {
		s.ContentPaddingAddition = "0"
	}
	if s.RekeyAfterTime == "" {
		s.RekeyAfterTime = "0"
	}
	if s.RekeyTimeout == "" {
		s.RekeyTimeout = "0"
	}
	if s.RejectAfterTime == "" {
		s.RejectAfterTime = "0"
	}
	if s.KeepaliveTimeout == "" {
		s.KeepaliveTimeout = "0"
	}
	if s.MaxHandshakeAttempts == "" {
		s.MaxHandshakeAttempts = "0"
	}
	if s.PersistentKeepaliveInterval == "" {
		s.PersistentKeepaliveInterval = "0"
	}
}

func (s *Settings) Check() error {
	err := s.Wireguard.Check()
	if err != nil {
		return err
	}

	if s.HeaderProtectionKey != "" {
		_, err := wgtypes.ParseKey(s.HeaderProtectionKey)
		if err != nil {
			return fmt.Errorf("parsing header protection key: %w", err)
		}
		const minimumHeaderProtectionPadding = 12
		if s.PaddingS1 < minimumHeaderProtectionPadding || s.PaddingS2 < minimumHeaderProtectionPadding ||
			s.PaddingS3 < minimumHeaderProtectionPadding || s.PaddingS4 < minimumHeaderProtectionPadding {
			return fmt.Errorf("S1-S4 must all be at least %d when header protection is enabled",
				minimumHeaderProtectionPadding)
		}
	}

	ranges := map[string]string{
		"content padding addition": s.ContentPaddingAddition,
		"rekey after time":         s.RekeyAfterTime,
		"rekey timeout":            s.RekeyTimeout,
		"reject after time":        s.RejectAfterTime,
		"keepalive timeout":        s.KeepaliveTimeout,
		"max handshake attempts":   s.MaxHandshakeAttempts,
	}
	for name, value := range ranges {
		var parsed amneziadevice.UintRange
		err := parsed.FromString(value)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", name, err)
		}
	}

	_, err = normalizePersistentKeepalive(s.PersistentKeepaliveInterval)
	if err != nil {
		return fmt.Errorf("parsing persistent keepalive interval: %w", err)
	}
	return nil
}

func normalizePersistentKeepalive(value string) (normalized string, err error) {
	var parsed amneziadevice.UintRange
	err = parsed.FromString(value)
	if err == nil {
		return value, nil
	}

	duration, durationErr := time.ParseDuration(value)
	if durationErr != nil {
		return "", err
	}
	if duration < 0 || duration%time.Second != 0 {
		return "", fmt.Errorf("duration must be a non-negative whole number of seconds: %s", value)
	}
	seconds := uint64(duration / time.Second)
	const maximumUint32 = 1<<32 - 1
	if seconds > maximumUint32 {
		return "", fmt.Errorf("duration exceeds %d seconds", maximumUint32)
	}
	return strconv.FormatUint(seconds, 10), nil
}
