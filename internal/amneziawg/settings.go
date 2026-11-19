package amneziawg

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/wireguard"
)

type Settings struct {
	Wireguard       wireguard.Settings
	JunkPacketCount uint16
	JunkPacketMin   uint16
	JunkPacketMax   uint16
	PaddingS1       uint16
	PaddingS2       uint16
	PaddingS3       uint16
	PaddingS4       uint16
	HeaderH1        string
	HeaderH2        string
	HeaderH3        string
	HeaderH4        string
	InitPacketI1    string
	InitPacketI2    string
	InitPacketI3    string
	InitPacketI4    string
	InitPacketI5    string
	// The following fields are only supported by AmneziaWG 3 and onwards.
	// Each one of them, except the header protection key, is a range of 32 bits
	// unsigned integers, where a zero value makes the AmneziaWG library use its
	// own default value.

	// HeaderProtectionKey is a 32 bytes hexadecimal encoded key, shared with the
	// server, which encrypts the low entropy fields of the message headers.
	// Once set, each of the s1 to s4 paddings is used as the cipher nonce and so
	// must be at least headerProtectionNonceSize bytes long.
	HeaderProtectionKey string
	// ContentPaddingAddition is an amount of random bytes added to the encrypted
	// content of sent packets, on top of the padding making it a multiple of
	// 16 bytes.
	ContentPaddingAddition [2]uint32
	// RekeyAfterTime is, in seconds, how long a session key pair is used for
	// before initiating a new handshake to rotate it. Defaults to 120 seconds.
	RekeyAfterTime [2]uint32
	// RekeyTimeout is, in seconds, how long to wait for a handshake response
	// before retransmitting the handshake initiation. Defaults to 5 seconds.
	RekeyTimeout [2]uint32
	// RejectAfterTime is, in seconds, how long after the last authenticated
	// packet received that all the key material is zeroed out, so any packet
	// from before is rejected. Defaults to 180 seconds.
	RejectAfterTime [2]uint32
	// KeepaliveTimeout is, in seconds, how long an idle tunnel waits before
	// sending an empty authenticated packet, to keep stateful network equipment
	// mappings alive. Defaults to 10 seconds.
	KeepaliveTimeout [2]uint32
	// MaxHandshakeAttempts is the amount of handshake retransmissions of the
	// underlying Wireguard implementation before giving up on a handshake,
	// from which a random value is picked, replacing its hard coded value of 18.
	// Each retransmission sends the AmneziaWG signature and junk packets
	// followed by the Wireguard initiation.
	MaxHandshakeAttempts [2]uint32
}

// uapiConfig returns the AmneziaWG specific configuration, in the UAPI format
// used by the library. The order of the lines does not matter to the library,
// it is only made deterministic for testing purposes.
func (s Settings) uapiConfig() string {
	uintFields := [...]struct {
		key   string
		value uint16
	}{
		{"jc", s.JunkPacketCount},
		{"jmin", s.JunkPacketMin},
		{"jmax", s.JunkPacketMax},
		{"s1", s.PaddingS1},
		{"s2", s.PaddingS2},
		{"s3", s.PaddingS3},
		{"s4", s.PaddingS4},
	}
	optionalFields := [...]struct {
		key   string
		value string
	}{
		{"h1", s.HeaderH1},
		{"h2", s.HeaderH2},
		{"h3", s.HeaderH3},
		{"h4", s.HeaderH4},
		{"i1", s.InitPacketI1},
		{"i2", s.InitPacketI2},
		{"i3", s.InitPacketI3},
		{"i4", s.InitPacketI4},
		{"i5", s.InitPacketI5},
		{"header_protection_key", s.HeaderProtectionKey},
		{"content_padding_addition", uint32RangeToString(s.ContentPaddingAddition)},
		{"rekey_after_time", uint32RangeToString(s.RekeyAfterTime)},
		{"rekey_timeout", uint32RangeToString(s.RekeyTimeout)},
		{"reject_after_time", uint32RangeToString(s.RejectAfterTime)},
		{"keepalive_timeout", uint32RangeToString(s.KeepaliveTimeout)},
		{"max_handshake_attempts", uint32RangeToString(s.MaxHandshakeAttempts)},
	}

	lines := make([]string, 0, len(uintFields)+len(optionalFields))

	for _, field := range uintFields {
		lines = append(lines, fmt.Sprintf("%s=%d", field.key, field.value))
	}

	for _, field := range optionalFields {
		if field.value == "" {
			// Not setting the line keeps the library default value.
			continue
		}
		lines = append(lines, field.key+"="+field.value)
	}

	return strings.Join(lines, "\n")
}

func (s *Settings) SetDefaults() {
	s.Wireguard.SetDefaults()
}

func (s Settings) Check() error {
	if err := s.Wireguard.Check(); err != nil {
		return err
	}

	if s.HeaderProtectionKey == "" {
		return nil
	}

	paddings := [...]struct {
		name  string
		value uint16
	}{
		{"s1", s.PaddingS1},
		{"s2", s.PaddingS2},
		{"s3", s.PaddingS3},
		{"s4", s.PaddingS4},
	}
	for _, padding := range paddings {
		// headerProtectionNonceSize is the amount of s1 to s4 padding bytes used as the
		// header protection cipher nonce, and so the minimum value of each one of them
		// when a header protection key is set.
		const headerProtectionNonceSize = 12
		if padding.value < headerProtectionNonceSize {
			return fmt.Errorf("header protection requires padding %s to be at least %d: got %d",
				padding.name, headerProtectionNonceSize, padding.value)
		}
	}

	return nil
}

// uint32RangeToString returns a range in the `number` or `min-max` format used
// by the AmneziaWG library range parameters, or an empty string for a zero
// range, in which case the library default value is used.
func uint32RangeToString(rangeValue [2]uint32) string {
	minimum, maximum := rangeValue[0], rangeValue[1]
	if minimum == 0 && maximum == 0 {
		return ""
	}
	if minimum == maximum {
		return strconv.FormatUint(uint64(minimum), 10)
	}
	return fmt.Sprintf("%d-%d", minimum, maximum)
}
