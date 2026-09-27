package settings

import (
	"fmt"
	"math"
	"net/netip"
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
	Wireguard       Wireguard `json:"wireguard"`
	JunkPacketCount *uint16   `json:"junk_packet_count"`
	JunkPacketMin   *uint16   `json:"junk_packet_min"`
	JunkPacketMax   *uint16   `json:"junk_packet_max"`
	PaddingS1       *uint16   `json:"padding_s1"`
	PaddingS2       *uint16   `json:"padding_s2"`
	PaddingS3       *uint16   `json:"padding_s3"`
	PaddingS4       *uint16   `json:"padding_s4"`
	HeaderH1        *string   `json:"header_h1"`
	HeaderH2        *string   `json:"header_h2"`
	HeaderH3        *string   `json:"header_h3"`
	HeaderH4        *string   `json:"header_h4"`
	InitPacketI1    *string   `json:"init_packet_i1"`
	InitPacketI2    *string   `json:"init_packet_i2"`
	InitPacketI3    *string   `json:"init_packet_i3"`
	InitPacketI4    *string   `json:"init_packet_i4"`
	InitPacketI5    *string   `json:"init_packet_i5"`
	// The following fields are only supported by AmneziaWG 3 and onwards.
	// Each one of them, except the header protection key, is a range of 32 bits
	// unsigned integers, read from the `number` or `min-max` format, and left
	// to 0 makes the AmneziaWG library use its own default value.

	// HeaderProtectionKey is a 32-byte base64 encoded key, shared with the server,
	// which encrypts the low entropy fields of the message headers.
	// Once set, each of the S1 to S4 paddings is used as the cipher nonce and so
	// must be greater than or equal to 12.
	HeaderProtectionKey *string `json:"header_protection_key"`
	// ContentPaddingAddition is an amount of random bytes added to the encrypted
	// content of sent packets, on top of the padding making it a multiple of
	// 16 bytes.
	ContentPaddingAddition *[2]uint32 `json:"content_padding_addition"`
	// RekeyAfterTime is, in seconds, how long a session key pair is used for
	// before initiating a new handshake to rotate it.
	RekeyAfterTime *[2]uint32 `json:"rekey_after_time"`
	// RekeyTimeout is, in seconds, how long to wait for a handshake response
	// before retransmitting the handshake initiation.
	RekeyTimeout *[2]uint32 `json:"rekey_timeout"`
	// RejectAfterTime is, in seconds, how long after the last authenticated
	// packet received that all the key material is zeroed out, so any packet
	// from before is rejected.
	RejectAfterTime *[2]uint32 `json:"reject_after_time"`
	// KeepaliveTimeout is, in seconds, how long an idle tunnel waits before
	// sending an empty authenticated packet, to keep stateful network equipment
	// mappings alive.
	KeepaliveTimeout *[2]uint32 `json:"keepalive_timeout"`
	// MaxHandshakeAttempts is the amount of handshake retransmissions of the
	// underlying Wireguard implementation before giving up on a handshake,
	// from which a random value is picked.
	MaxHandshakeAttempts *[2]uint32 `json:"max_handshake_attempts"`
	// PersistentKeepaliveInterval is the range, in seconds, from which the
	// interval between persistent keepalive packets is selected. It is the
	// source of truth for AmneziaWG; the nested Wireguard duration is only
	// accepted as legacy input and normalized into this range.
	PersistentKeepaliveInterval *[2]uint32 `json:"persistent_keep_alive_interval"`
	// RandomTrailers controls whether random trailers are added to packets.
	RandomTrailers *bool `json:"random_trailers"`
	// DisableCookies controls whether cookie reply packets are disabled.
	DisableCookies *bool `json:"disable_cookies"`
	// DNSServers contains DNS servers read from the AmneziaWG configuration file.
	// They are applied to the top-level DNS settings after all sources are read.
	DNSServers []netip.AddrPort `json:"-"`
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
		"AMNEZIAWG_H1":                    &a.HeaderH1,
		"AMNEZIAWG_H2":                    &a.HeaderH2,
		"AMNEZIAWG_H3":                    &a.HeaderH3,
		"AMNEZIAWG_H4":                    &a.HeaderH4,
		"AMNEZIAWG_I1":                    &a.InitPacketI1,
		"AMNEZIAWG_I2":                    &a.InitPacketI2,
		"AMNEZIAWG_I3":                    &a.InitPacketI3,
		"AMNEZIAWG_I4":                    &a.InitPacketI4,
		"AMNEZIAWG_I5":                    &a.InitPacketI5,
		"AMNEZIAWG_HEADER_PROTECTION_KEY": &a.HeaderProtectionKey,
	}
	opt := reader.ForceLowercase(false)
	for key, dst := range stringFields {
		*dst = r.Get(key, opt)
	}

	rangeFields := map[string]**[2]uint32{
		"AMNEZIAWG_CONTENT_PADDING_ADDITION": &a.ContentPaddingAddition,
		"AMNEZIAWG_REKEY_AFTER_TIME":         &a.RekeyAfterTime,
		"AMNEZIAWG_REKEY_TIMEOUT":            &a.RekeyTimeout,
		"AMNEZIAWG_REJECT_AFTER_TIME":        &a.RejectAfterTime,
		"AMNEZIAWG_KEEPALIVE_TIMEOUT":        &a.KeepaliveTimeout,
		"AMNEZIAWG_MAX_HANDSHAKE_ATTEMPTS":   &a.MaxHandshakeAttempts,
	}
	for key, dst := range rangeFields {
		*dst, err = parseUint32Range(r.Get(key, opt))
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}

	a.PersistentKeepaliveInterval, err = parsePersistentKeepaliveRange(
		r.Get("AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL", opt))
	if err != nil {
		return fmt.Errorf("AMNEZIAWG_PERSISTENT_KEEPALIVE_INTERVAL: %w", err)
	}

	a.RandomTrailers, err = readAmneziaWGBool(r, "AMNEZIAWG_RANDOM_TRAILERS")
	if err != nil {
		return err
	}

	a.DisableCookies, err = readAmneziaWGBool(r, "AMNEZIAWG_DISABLE_COOKIES")
	if err != nil {
		return err
	}

	a.DNSServers, err = parseAmneziaWGDNSServers(r.Get("AMNEZIAWG_DNS", opt))
	if err != nil {
		return fmt.Errorf("AMNEZIAWG_DNS: %w", err)
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
		DNSServers:                  gosettings.CopySlice(a.DNSServers),
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
	a.normalizePersistentKeepalive(other.PersistentKeepaliveInterval,
		other.Wireguard.PersistentKeepaliveInterval)
	a.RandomTrailers = gosettings.OverrideWithPointer(a.RandomTrailers, other.RandomTrailers)
	a.DisableCookies = gosettings.OverrideWithPointer(a.DisableCookies, other.DisableCookies)
	a.DNSServers = gosettings.OverrideWithSlice(a.DNSServers, other.DNSServers)
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
	// The following defaults are the AmneziaWG library ones, mirrored here so
	// the effective values are visible.

	// ContentPaddingAddition zero value means no extra padding is added.
	a.ContentPaddingAddition = gosettings.DefaultPointer(a.ContentPaddingAddition, [2]uint32{})

	const defaultRekeyAfterTime = 120
	a.RekeyAfterTime = gosettings.DefaultPointer(a.RekeyAfterTime, uint32Range(defaultRekeyAfterTime))

	const defaultRekeyTimeout = 5
	a.RekeyTimeout = gosettings.DefaultPointer(a.RekeyTimeout, uint32Range(defaultRekeyTimeout))

	const defaultRejectAfterTime = 180
	a.RejectAfterTime = gosettings.DefaultPointer(a.RejectAfterTime, uint32Range(defaultRejectAfterTime))

	const defaultKeepaliveTimeout = 10
	a.KeepaliveTimeout = gosettings.DefaultPointer(a.KeepaliveTimeout, uint32Range(defaultKeepaliveTimeout))

	const defaultMaxHandshakeAttempts = 18
	a.MaxHandshakeAttempts = gosettings.DefaultPointer(a.MaxHandshakeAttempts, uint32Range(defaultMaxHandshakeAttempts))
	a.normalizePersistentKeepalive(a.PersistentKeepaliveInterval,
		a.Wireguard.PersistentKeepaliveInterval)
	a.RandomTrailers = gosettings.DefaultPointer(a.RandomTrailers, false)
	a.DisableCookies = gosettings.DefaultPointer(a.DisableCookies, false)
	a.DNSServers = gosettings.DefaultSlice(a.DNSServers, []netip.AddrPort{})
}

func (a *AmneziaWg) normalizePersistentKeepalive(interval *[2]uint32,
	legacyInterval *time.Duration,
) {
	switch {
	case interval != nil:
		a.PersistentKeepaliveInterval = gosettings.CopyPointer(interval)
		a.Wireguard.PersistentKeepaliveInterval = new(time.Duration)
	case legacyInterval != nil:
		persistentKeepaliveInterval, err := persistentKeepaliveDurationToRange(*legacyInterval)
		if err != nil {
			a.PersistentKeepaliveInterval = gosettings.DefaultPointer(a.PersistentKeepaliveInterval, [2]uint32{})
			return
		}
		a.PersistentKeepaliveInterval = persistentKeepaliveInterval
		a.Wireguard.PersistentKeepaliveInterval = new(time.Duration)
	}
}

func (a AmneziaWg) toLinesNode() (node *gotree.Node) {
	node = gotree.New("AmneziaWG settings:")
	node.AppendNode(a.Wireguard.toLinesNode())

	junkPaddingFields := []struct {
		key   string
		value *uint16
	}{
		{"JC", a.JunkPacketCount},
		{"JMIN", a.JunkPacketMin},
		{"JMAX", a.JunkPacketMax},
		{"S1", a.PaddingS1},
		{"S2", a.PaddingS2},
		{"S3", a.PaddingS3},
		{"S4", a.PaddingS4},
	}
	for _, field := range junkPaddingFields {
		node.Appendf("%s: %d", field.key, *field.value)
	}

	stringFields := []struct {
		key   string
		value *string
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
	}
	for _, field := range stringFields {
		node.Appendf("%s: %s", field.key, *field.value)
	}

	node.Appendf("Header protection key: %s",
		gosettings.ObfuscateKey(*a.HeaderProtectionKey))

	rangeFields := []struct {
		key   string
		value *[2]uint32
	}{
		{"Content padding addition", a.ContentPaddingAddition},
		{"Rekey after time (seconds)", a.RekeyAfterTime},
		{"Rekey timeout (seconds)", a.RekeyTimeout},
		{"Reject after time (seconds)", a.RejectAfterTime},
		{"Keepalive timeout (seconds)", a.KeepaliveTimeout},
		{"Max handshake attempts", a.MaxHandshakeAttempts},
	}
	for _, field := range rangeFields {
		node.Appendf("%s: %s", field.key, uint32RangeToString(field.value))
	}
	node.Appendf("Persistent keepalive interval (seconds): %s",
		uint32RangeToString(a.PersistentKeepaliveInterval))
	node.Appendf("Random trailers: %s", gosettings.BoolToYesNo(a.RandomTrailers))
	node.Appendf("Disable cookies: %s", gosettings.BoolToYesNo(a.DisableCookies))

	return node
}

// uint32Range returns a range with both bounds set to the given value.
func uint32Range(value uint32) [2]uint32 {
	return [2]uint32{value, value}
}

// uint32RangeToString returns a range in the `number` or `min-max` format, as
// used by the AmneziaWG library range parameters.
func uint32RangeToString(value *[2]uint32) string {
	minimum, maximum := value[0], value[1]
	if minimum == maximum {
		return strconv.FormatUint(uint64(minimum), 10)
	}
	return fmt.Sprintf("%d-%d", minimum, maximum)
}

func (a AmneziaWg) validate(vpnProvider string, ipv6Supported bool) error {
	const amneziaWG = true
	err := a.Wireguard.validate(vpnProvider, ipv6Supported, amneziaWG)
	if err != nil {
		return fmt.Errorf("wireguard settings: %w", err)
	}

	persistentKeepaliveMinimum := a.PersistentKeepaliveInterval[0]
	persistentKeepaliveMaximum := a.PersistentKeepaliveInterval[1]
	if persistentKeepaliveMinimum > persistentKeepaliveMaximum {
		return fmt.Errorf("persistent keepalive maximum %d must be greater than or equal to minimum %d",
			persistentKeepaliveMaximum, persistentKeepaliveMinimum)
	}
	if *a.Wireguard.PersistentKeepaliveInterval != 0 {
		_, err = persistentKeepaliveDurationToRange(*a.Wireguard.PersistentKeepaliveInterval)
		if err != nil {
			return fmt.Errorf("legacy persistent keepalive interval: %w", err)
		}
	}

	err = validateHeaderProtectionKey(*a.HeaderProtectionKey)
	if err != nil {
		return fmt.Errorf("header protection key: %w", err)
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

	return nil
}

// parseUint32Range parses a value in the `number` or `min-max` format used by
// the AmneziaWG range parameters, such as 10 or 10-30, where both numbers are
// 32 bits unsigned integers. It returns nil for a nil value.
//
// TODO: move this function to the github.com/qdm12/gosettings package.
func parseUint32Range(value *string) (rangeValue *[2]uint32, err error) {
	if value == nil {
		return nil, nil //nolint:nilnil // a nil value means the setting is not set
	}

	fields := strings.Split(*value, "-")
	if len(fields) > 2 { //nolint:mnd // a range is a minimum and a maximum
		return nil, fmt.Errorf("%q must be a number or a min-max pair of numbers", *value)
	}

	minimum, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("minimum %q is not a valid 32 bits unsigned integer", fields[0])
	}
	rangeValue = new([2]uint32)
	rangeValue[0] = uint32(minimum)
	rangeValue[1] = uint32(minimum)

	if len(fields) == 1 {
		return rangeValue, nil
	}

	maximum, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("maximum %q is not a valid 32 bits unsigned integer", fields[1])
	}
	if maximum < minimum {
		return nil, fmt.Errorf("maximum %d must be greater than or equal to minimum %d",
			maximum, minimum)
	}
	rangeValue[1] = uint32(maximum)

	return rangeValue, nil
}

func parsePersistentKeepaliveRange(value *string) (rangeValue *[2]uint32, err error) {
	if value == nil {
		return nil, nil //nolint:nilnil // a nil value means the setting is not set
	}

	duration, durationErr := time.ParseDuration(*value)
	if durationErr != nil {
		return parseUint32Range(value)
	}
	return persistentKeepaliveDurationToRange(duration)
}

func persistentKeepaliveDurationToRange(duration time.Duration) (rangeValue *[2]uint32, err error) {
	if duration < 0 {
		return nil, fmt.Errorf("duration %s is negative", duration)
	}
	if duration%time.Second != 0 {
		return nil, fmt.Errorf("duration %s must be a whole number of seconds", duration)
	}
	seconds := duration / time.Second
	if seconds > math.MaxUint32 {
		return nil, fmt.Errorf("duration %s exceeds %d seconds", duration, uint64(math.MaxUint32))
	}

	return new([2]uint32{uint32(seconds), uint32(seconds)}), nil
}

func readAmneziaWGBool(r *reader.Reader, key string) (value *bool, err error) {
	switch r.String(key) {
	case "0":
		return new(false), nil
	case "1":
		return new(true), nil
	default:
		return r.BoolPtr(key)
	}
}

func parseAmneziaWGDNSServers(value *string) (servers []netip.AddrPort, err error) {
	if value == nil {
		return nil, nil
	}

	for serverString := range strings.SplitSeq(*value, ",") {
		serverString = strings.TrimSpace(serverString)
		server, err := netip.ParseAddr(serverString)
		if err != nil {
			return nil, fmt.Errorf("parsing address %q: %w", serverString, err)
		}
		const dnsPort = 53
		servers = append(servers, netip.AddrPortFrom(server, dnsPort))
	}

	return servers, nil
}

// validateHeaderProtectionKey checks the base64 encoded header protection key,
// only used by AmneziaWG 3 and onwards. An empty key disables it.
func validateHeaderProtectionKey(key string) error {
	if key == "" {
		return nil
	}

	_, err := wgtypes.ParseKey(key)
	if err != nil {
		return fmt.Errorf("must be a 32-byte base64 encoded key: %w", err)
	}
	return nil
}
