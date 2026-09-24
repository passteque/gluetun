package settings

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type AmneziaWg struct {
	// Wireguard contains the configuration for Wireguard, given
	// AmneziaWg is based on Wireguard
	Wireguard                   Wireguard `json:"wireguard"`
	JunkPacketCount             *uint16   `json:"junk_packet_count"`
	JunkPacketMin               *uint16   `json:"junk_packet_min"`
	JunkPacketMax               *uint16   `json:"junk_packet_max"`
	PaddingS1                   *uint16   `json:"padding_s1"`
	PaddingS2                   *uint16   `json:"padding_s2"`
	PaddingS3                   *uint16   `json:"padding_s3"`
	PaddingS4                   *uint16   `json:"padding_s4"`
	HeaderH1                    *string   `json:"header_h1"`
	HeaderH2                    *string   `json:"header_h2"`
	HeaderH3                    *string   `json:"header_h3"`
	HeaderH4                    *string   `json:"header_h4"`
	InitPacketI1                *string   `json:"init_packet_i1"`
	InitPacketI2                *string   `json:"init_packet_i2"`
	InitPacketI3                *string   `json:"init_packet_i3"`
	InitPacketI4                *string   `json:"init_packet_i4"`
	InitPacketI5                *string   `json:"init_packet_i5"`
	HeaderProtectionKey         *string   `json:"header_protection_key"`
	ContentPaddingAddition      *string   `json:"content_padding_addition"`
	RekeyAfterTime              *string   `json:"rekey_after_time"`
	RekeyTimeout                *string   `json:"rekey_timeout"`
	RejectAfterTime             *string   `json:"reject_after_time"`
	KeepaliveTimeout            *string   `json:"keepalive_timeout"`
	MaxHandshakeAttempts        *string   `json:"max_handshake_attempts"`
	PersistentKeepaliveInterval *string   `json:"persistent_keepalive_interval"`
	RandomTrailers              *bool     `json:"random_trailers"`
	DisableCookies              *bool     `json:"disable_cookies"`
}

func (a *AmneziaWg) read(r *reader.Reader) (err error) {
	const amneziawg = true
	err = a.Wireguard.read(r, amneziawg)
	if err != nil {
		return err // do not wrap this error
	}

	uint16Fields := map[string]**uint16{
		"AMNEZIAWG_JC":   &a.JunkPacketCount,
		"AMNEZIAWG_JMIN": &a.JunkPacketMin,
		"AMNEZIAWG_JMAX": &a.JunkPacketMax,
		"AMNEZIAWG_S1":   &a.PaddingS1,
		"AMNEZIAWG_S2":   &a.PaddingS2,
		"AMNEZIAWG_S3":   &a.PaddingS3,
		"AMNEZIAWG_S4":   &a.PaddingS4,
	}
	for key, dst := range uint16Fields {
		*dst, err = r.Uint16Ptr(key)
		if err != nil {
			return err
		}
	}
	stringFields := map[string]**string{
		"AMNEZIAWG_H1":                            &a.HeaderH1,
		"AMNEZIAWG_H2":                            &a.HeaderH2,
		"AMNEZIAWG_H3":                            &a.HeaderH3,
		"AMNEZIAWG_H4":                            &a.HeaderH4,
		"AMNEZIAWG_I1":                            &a.InitPacketI1,
		"AMNEZIAWG_I2":                            &a.InitPacketI2,
		"AMNEZIAWG_I3":                            &a.InitPacketI3,
		"AMNEZIAWG_I4":                            &a.InitPacketI4,
		"AMNEZIAWG_I5":                            &a.InitPacketI5,
		"AMNEZIAWG_HEADER_PROTECTION_KEY":         &a.HeaderProtectionKey,
		"AMNEZIAWG_CONTENT_PADDING_ADDITION":      &a.ContentPaddingAddition,
		"AMNEZIAWG_REKEY_AFTER_TIME":              &a.RekeyAfterTime,
		"AMNEZIAWG_REKEY_TIMEOUT":                 &a.RekeyTimeout,
		"AMNEZIAWG_REJECT_AFTER_TIME":             &a.RejectAfterTime,
		"AMNEZIAWG_KEEPALIVE_TIMEOUT":             &a.KeepaliveTimeout,
		"AMNEZIAWG_MAX_HANDSHAKE_ATTEMPTS":        &a.MaxHandshakeAttempts,
		"AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL": &a.PersistentKeepaliveInterval,
	}
	opt := reader.ForceLowercase(false)
	for key, dst := range stringFields {
		*dst = r.Get(key, opt)
	}
	a.RandomTrailers, err = r.BoolPtr("AMNEZIAWG_RANDOM_TRAILERS")
	if err != nil {
		return err
	}
	a.DisableCookies, err = r.BoolPtr("AMNEZIAWG_DISABLE_COOKIES")
	if err != nil {
		return err
	}
	return nil
}

func (a AmneziaWg) copy() (copied AmneziaWg) {
	return AmneziaWg{
		Wireguard:                   a.Wireguard.copy(),
		JunkPacketCount:             gosettings.CopyPointer(a.JunkPacketCount),
		JunkPacketMin:               gosettings.CopyPointer(a.JunkPacketMin),
		JunkPacketMax:               gosettings.CopyPointer(a.JunkPacketMax),
		PaddingS1:                   gosettings.CopyPointer(a.PaddingS1),
		PaddingS2:                   gosettings.CopyPointer(a.PaddingS2),
		PaddingS3:                   gosettings.CopyPointer(a.PaddingS3),
		PaddingS4:                   gosettings.CopyPointer(a.PaddingS4),
		HeaderH1:                    gosettings.CopyPointer(a.HeaderH1),
		HeaderH2:                    gosettings.CopyPointer(a.HeaderH2),
		HeaderH3:                    gosettings.CopyPointer(a.HeaderH3),
		HeaderH4:                    gosettings.CopyPointer(a.HeaderH4),
		InitPacketI1:                gosettings.CopyPointer(a.InitPacketI1),
		InitPacketI2:                gosettings.CopyPointer(a.InitPacketI2),
		InitPacketI3:                gosettings.CopyPointer(a.InitPacketI3),
		InitPacketI4:                gosettings.CopyPointer(a.InitPacketI4),
		InitPacketI5:                gosettings.CopyPointer(a.InitPacketI5),
		HeaderProtectionKey:         gosettings.CopyPointer(a.HeaderProtectionKey),
		ContentPaddingAddition:      gosettings.CopyPointer(a.ContentPaddingAddition),
		RekeyAfterTime:              gosettings.CopyPointer(a.RekeyAfterTime),
		RekeyTimeout:                gosettings.CopyPointer(a.RekeyTimeout),
		RejectAfterTime:             gosettings.CopyPointer(a.RejectAfterTime),
		KeepaliveTimeout:            gosettings.CopyPointer(a.KeepaliveTimeout),
		MaxHandshakeAttempts:        gosettings.CopyPointer(a.MaxHandshakeAttempts),
		PersistentKeepaliveInterval: gosettings.CopyPointer(a.PersistentKeepaliveInterval),
		RandomTrailers:              gosettings.CopyPointer(a.RandomTrailers),
		DisableCookies:              gosettings.CopyPointer(a.DisableCookies),
	}
}

func (a *AmneziaWg) overrideWith(other AmneziaWg) {
	a.Wireguard.overrideWith(other.Wireguard)
	a.JunkPacketCount = gosettings.OverrideWithPointer(a.JunkPacketCount, other.JunkPacketCount)
	a.JunkPacketMin = gosettings.OverrideWithPointer(a.JunkPacketMin, other.JunkPacketMin)
	a.JunkPacketMax = gosettings.OverrideWithPointer(a.JunkPacketMax, other.JunkPacketMax)
	a.PaddingS1 = gosettings.OverrideWithPointer(a.PaddingS1, other.PaddingS1)
	a.PaddingS2 = gosettings.OverrideWithPointer(a.PaddingS2, other.PaddingS2)
	a.PaddingS3 = gosettings.OverrideWithPointer(a.PaddingS3, other.PaddingS3)
	a.PaddingS4 = gosettings.OverrideWithPointer(a.PaddingS4, other.PaddingS4)
	a.HeaderH1 = gosettings.OverrideWithPointer(a.HeaderH1, other.HeaderH1)
	a.HeaderH2 = gosettings.OverrideWithPointer(a.HeaderH2, other.HeaderH2)
	a.HeaderH3 = gosettings.OverrideWithPointer(a.HeaderH3, other.HeaderH3)
	a.HeaderH4 = gosettings.OverrideWithPointer(a.HeaderH4, other.HeaderH4)
	a.InitPacketI1 = gosettings.OverrideWithPointer(a.InitPacketI1, other.InitPacketI1)
	a.InitPacketI2 = gosettings.OverrideWithPointer(a.InitPacketI2, other.InitPacketI2)
	a.InitPacketI3 = gosettings.OverrideWithPointer(a.InitPacketI3, other.InitPacketI3)
	a.InitPacketI4 = gosettings.OverrideWithPointer(a.InitPacketI4, other.InitPacketI4)
	a.InitPacketI5 = gosettings.OverrideWithPointer(a.InitPacketI5, other.InitPacketI5)
	a.HeaderProtectionKey = gosettings.OverrideWithPointer(a.HeaderProtectionKey, other.HeaderProtectionKey)
	a.ContentPaddingAddition = gosettings.OverrideWithPointer(a.ContentPaddingAddition, other.ContentPaddingAddition)
	a.RekeyAfterTime = gosettings.OverrideWithPointer(a.RekeyAfterTime, other.RekeyAfterTime)
	a.RekeyTimeout = gosettings.OverrideWithPointer(a.RekeyTimeout, other.RekeyTimeout)
	a.RejectAfterTime = gosettings.OverrideWithPointer(a.RejectAfterTime, other.RejectAfterTime)
	a.KeepaliveTimeout = gosettings.OverrideWithPointer(a.KeepaliveTimeout, other.KeepaliveTimeout)
	a.MaxHandshakeAttempts = gosettings.OverrideWithPointer(a.MaxHandshakeAttempts, other.MaxHandshakeAttempts)
	a.PersistentKeepaliveInterval = gosettings.OverrideWithPointer(a.PersistentKeepaliveInterval,
		other.PersistentKeepaliveInterval)
	a.RandomTrailers = gosettings.OverrideWithPointer(a.RandomTrailers, other.RandomTrailers)
	a.DisableCookies = gosettings.OverrideWithPointer(a.DisableCookies, other.DisableCookies)
}

func (a *AmneziaWg) setDefaults(vpnProvider string) {
	a.Wireguard.setDefaults(vpnProvider)
	a.Wireguard.Implementation = "userspace" // unused except in logs
	a.JunkPacketCount = gosettings.DefaultPointer(a.JunkPacketCount, 0)
	a.JunkPacketMin = gosettings.DefaultPointer(a.JunkPacketMin, 0)
	a.JunkPacketMax = gosettings.DefaultPointer(a.JunkPacketMax, 0)
	a.PaddingS1 = gosettings.DefaultPointer(a.PaddingS1, 0)
	a.PaddingS2 = gosettings.DefaultPointer(a.PaddingS2, 0)
	a.PaddingS3 = gosettings.DefaultPointer(a.PaddingS3, 0)
	a.PaddingS4 = gosettings.DefaultPointer(a.PaddingS4, 0)
	a.HeaderH1 = gosettings.DefaultPointer(a.HeaderH1, "")
	a.HeaderH2 = gosettings.DefaultPointer(a.HeaderH2, "")
	a.HeaderH3 = gosettings.DefaultPointer(a.HeaderH3, "")
	a.HeaderH4 = gosettings.DefaultPointer(a.HeaderH4, "")
	a.InitPacketI1 = gosettings.DefaultPointer(a.InitPacketI1, "")
	a.InitPacketI2 = gosettings.DefaultPointer(a.InitPacketI2, "")
	a.InitPacketI3 = gosettings.DefaultPointer(a.InitPacketI3, "")
	a.InitPacketI4 = gosettings.DefaultPointer(a.InitPacketI4, "")
	a.InitPacketI5 = gosettings.DefaultPointer(a.InitPacketI5, "")
	a.HeaderProtectionKey = gosettings.DefaultPointer(a.HeaderProtectionKey, "")
	a.ContentPaddingAddition = gosettings.DefaultPointer(a.ContentPaddingAddition, "0")
	a.RekeyAfterTime = gosettings.DefaultPointer(a.RekeyAfterTime, "0")
	a.RekeyTimeout = gosettings.DefaultPointer(a.RekeyTimeout, "0")
	a.RejectAfterTime = gosettings.DefaultPointer(a.RejectAfterTime, "0")
	a.KeepaliveTimeout = gosettings.DefaultPointer(a.KeepaliveTimeout, "0")
	a.MaxHandshakeAttempts = gosettings.DefaultPointer(a.MaxHandshakeAttempts, "0")
	a.PersistentKeepaliveInterval = gosettings.DefaultPointer(a.PersistentKeepaliveInterval, "0")
	a.RandomTrailers = gosettings.DefaultPointer(a.RandomTrailers, false)
	a.DisableCookies = gosettings.DefaultPointer(a.DisableCookies, false)
}

func (a AmneziaWg) toLinesNode() (node *gotree.Node) {
	node = gotree.New("AmneziaWG settings:")
	node.AppendNode(a.Wireguard.toLinesNode())

	uintFields := []struct {
		key string
		val *uint16
	}{
		{"JC", a.JunkPacketCount},
		{"JMIN", a.JunkPacketMin},
		{"JMAX", a.JunkPacketMax},
		{"S1", a.PaddingS1},
		{"S2", a.PaddingS2},
		{"S3", a.PaddingS3},
		{"S4", a.PaddingS4},
	}
	for _, f := range uintFields {
		node.Appendf("%s: %d", f.key, *f.val)
	}

	stringFields := []struct {
		key string
		val *string
	}{
		{"H1", a.HeaderH1},
		{"H2", a.HeaderH2},
		{"H3", a.HeaderH3},
		{"H4", a.HeaderH4},
		{"I1", a.InitPacketI1},
		{"I2", a.InitPacketI2},
		{"I3", a.InitPacketI3},
		{"I4", a.InitPacketI4},
		{"I5", a.InitPacketI5},
		{"Content padding addition", a.ContentPaddingAddition},
		{"Rekey after time", a.RekeyAfterTime},
		{"Rekey timeout", a.RekeyTimeout},
		{"Reject after time", a.RejectAfterTime},
		{"Keepalive timeout", a.KeepaliveTimeout},
		{"Max handshake attempts", a.MaxHandshakeAttempts},
		{"Persistent keepalive interval", a.PersistentKeepaliveInterval},
	}
	for _, f := range stringFields {
		node.Appendf("%s: %s", f.key, *f.val)
	}
	if *a.HeaderProtectionKey != "" {
		node.Append("Header protection key: set")
	}
	node.Appendf("Random trailers: %t", *a.RandomTrailers)
	node.Appendf("Disable cookies: %t", *a.DisableCookies)

	return node
}

func (a AmneziaWg) validate(vpnProvider string, ipv6Supported bool) error {
	const amneziaWG = true
	err := a.Wireguard.validate(vpnProvider, ipv6Supported, amneziaWG)
	if err != nil {
		return fmt.Errorf("wireguard settings: %w", err)
	}

	if *a.JunkPacketCount == 0 {
		if *a.JunkPacketMin != 0 || *a.JunkPacketMax != 0 {
			return fmt.Errorf("junk packet count must be set when junk packet min or max is set: "+
				"jc=%d and jmin=%d and jmax=%d", a.JunkPacketCount, *a.JunkPacketMin, *a.JunkPacketMax)
		}
	} else {
		if *a.JunkPacketMin == 0 || *a.JunkPacketMax == 0 {
			return fmt.Errorf("junk packet min and max must be set when junk packet count is set: "+
				"jc=%d and jmin=%d and jmax=%d", a.JunkPacketCount, *a.JunkPacketMin, *a.JunkPacketMax)
		} else if *a.JunkPacketMin > *a.JunkPacketMax {
			return fmt.Errorf("junk packet minimum must be lower than or equal to maximum: "+
				"jmin=%d and jmax=%d", *a.JunkPacketMin, *a.JunkPacketMax)
		}
	}

	nameToHeaderRange := map[string]string{
		"h1": *a.HeaderH1,
		"h2": *a.HeaderH2,
		"h3": *a.HeaderH3,
		"h4": *a.HeaderH4,
	}
	for name, headerRange := range nameToHeaderRange {
		if headerRange == "" {
			continue
		}
		fields := strings.Split(headerRange, "-")
		switch len(fields) {
		case 1:
			_, err := strconv.Atoi(fields[0])
			if err != nil {
				return fmt.Errorf("header range is malformed: "+
					"%s value %s is not a number", name, headerRange)
			}
		case 2: //nolint:mnd
			for _, field := range fields {
				_, err := strconv.Atoi(field)
				if err != nil {
					return fmt.Errorf("header range is malformed: "+
						"%s value %s is not a valid range", name, headerRange)
				}
			}
		default:
			return fmt.Errorf("header range is malformed: "+
				"%s value %s must be in the form n or n-m", name, headerRange)
		}
	}

	return validateAmneziaWG3(a)
}

func validateAmneziaWG3(settings AmneziaWg) error {
	if *settings.HeaderProtectionKey != "" {
		_, err := wgtypes.ParseKey(*settings.HeaderProtectionKey)
		if err != nil {
			return fmt.Errorf("header protection key is invalid: %w", err)
		}
		const minimumHeaderProtectionPadding = 12
		if *settings.PaddingS1 < minimumHeaderProtectionPadding || *settings.PaddingS2 < minimumHeaderProtectionPadding ||
			*settings.PaddingS3 < minimumHeaderProtectionPadding || *settings.PaddingS4 < minimumHeaderProtectionPadding {
			return fmt.Errorf("S1-S4 must all be at least %d when header protection is enabled",
				minimumHeaderProtectionPadding)
		}
	}

	ranges := map[string]string{
		"content padding addition": *settings.ContentPaddingAddition,
		"rekey after time":         *settings.RekeyAfterTime,
		"rekey timeout":            *settings.RekeyTimeout,
		"reject after time":        *settings.RejectAfterTime,
		"keepalive timeout":        *settings.KeepaliveTimeout,
		"max handshake attempts":   *settings.MaxHandshakeAttempts,
	}
	for name, value := range ranges {
		err := validateUint32Range(value)
		if err != nil {
			return fmt.Errorf("%s is invalid: %w", name, err)
		}
	}

	err := validatePersistentKeepalive(*settings.PersistentKeepaliveInterval)
	if err != nil {
		return fmt.Errorf("persistent keepalive interval is invalid: %w", err)
	}

	return nil
}

func validatePersistentKeepalive(value string) error {
	err := validateUint32Range(value)
	if err == nil {
		return nil
	}

	duration, durationErr := time.ParseDuration(value)
	if durationErr != nil {
		return err
	}
	if duration < 0 || duration%time.Second != 0 {
		return fmt.Errorf("duration must be a non-negative whole number of seconds: %s", value)
	}
	seconds := uint64(duration / time.Second)
	const maximumUint32 = 1<<32 - 1
	if seconds > maximumUint32 {
		return fmt.Errorf("duration exceeds %d seconds", maximumUint32)
	}
	return nil
}

func validateUint32Range(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("value %q must be a number or a range n-m", value)
	}

	lower, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("parsing lower bound: %w", err)
	}
	upper := lower
	if len(parts) == 2 { //nolint:mnd
		upper, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("parsing upper bound: %w", err)
		}
	}
	if upper < lower {
		return fmt.Errorf("upper bound %d is lower than lower bound %d", upper, lower)
	}
	return nil
}
