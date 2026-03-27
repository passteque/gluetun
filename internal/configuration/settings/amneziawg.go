package settings

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
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
		"AMNEZIAWG_H1": &a.HeaderH1,
		"AMNEZIAWG_H2": &a.HeaderH2,
		"AMNEZIAWG_H3": &a.HeaderH3,
		"AMNEZIAWG_H4": &a.HeaderH4,
		"AMNEZIAWG_I1": &a.InitPacketI1,
		"AMNEZIAWG_I2": &a.InitPacketI2,
		"AMNEZIAWG_I3": &a.InitPacketI3,
		"AMNEZIAWG_I4": &a.InitPacketI4,
		"AMNEZIAWG_I5": &a.InitPacketI5,
	}
	opt := reader.ForceLowercase(false)
	for key, dst := range stringFields {
		*dst = r.Get(key, opt)
	}
	return nil
}

func (a AmneziaWg) copy() (copied AmneziaWg) {
	return AmneziaWg{
		Wireguard:       a.Wireguard.copy(),
		JunkPacketCount: gosettings.CopyPointer(a.JunkPacketCount),
		JunkPacketMin:   gosettings.CopyPointer(a.JunkPacketMin),
		JunkPacketMax:   gosettings.CopyPointer(a.JunkPacketMax),
		PaddingS1:       gosettings.CopyPointer(a.PaddingS1),
		PaddingS2:       gosettings.CopyPointer(a.PaddingS2),
		PaddingS3:       gosettings.CopyPointer(a.PaddingS3),
		PaddingS4:       gosettings.CopyPointer(a.PaddingS4),
		HeaderH1:        gosettings.CopyPointer(a.HeaderH1),
		HeaderH2:        gosettings.CopyPointer(a.HeaderH2),
		HeaderH3:        gosettings.CopyPointer(a.HeaderH3),
		HeaderH4:        gosettings.CopyPointer(a.HeaderH4),
		InitPacketI1:    gosettings.CopyPointer(a.InitPacketI1),
		InitPacketI2:    gosettings.CopyPointer(a.InitPacketI2),
		InitPacketI3:    gosettings.CopyPointer(a.InitPacketI3),
		InitPacketI4:    gosettings.CopyPointer(a.InitPacketI4),
		InitPacketI5:    gosettings.CopyPointer(a.InitPacketI5),
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
	}
	for _, f := range stringFields {
		node.Appendf("%s: %s", f.key, *f.val)
	}

	return node
}

var (
	ErrAmenziawgImplementationNotValid = errors.New("AmneziaWG implementation is not valid")
	ErrJunkPacketBounds                = errors.New("junk packet minimum must be lower than or equal to maximum")
	ErrJunkPacketMinMaxNotSet          = errors.New("junk packet min and max must be set when junk packet count is set")
	ErrJunkPacketCountNotSet           = errors.New("junk packet count must be set when junk packet min or max is set")
	ErrHeaderRangeMalformed            = errors.New("header range is malformed")
)

func (a AmneziaWg) validate(vpnProvider string, ipv6Supported bool) error {
	const amneziaWG = true
	err := a.Wireguard.validate(vpnProvider, ipv6Supported, amneziaWG)
	if err != nil {
		return fmt.Errorf("wireguard settings: %w", err)
	}

	if *a.JunkPacketCount == 0 {
		if *a.JunkPacketMin != 0 || *a.JunkPacketMax != 0 {
			return fmt.Errorf("%w: jc=%d and jmin=%d and jmax=%d",
				ErrJunkPacketCountNotSet, a.JunkPacketCount, *a.JunkPacketMin, *a.JunkPacketMax)
		}
	} else {
		if *a.JunkPacketMin == 0 || *a.JunkPacketMax == 0 {
			return fmt.Errorf("%w: jc=%d and jmin=%d and jmax=%d",
				ErrJunkPacketMinMaxNotSet, a.JunkPacketCount, *a.JunkPacketMin, *a.JunkPacketMax)
		} else if *a.JunkPacketMin > *a.JunkPacketMax {
			return fmt.Errorf("%w: jmin=%d and jmax=%d",
				ErrJunkPacketBounds, *a.JunkPacketMin, *a.JunkPacketMax)
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
				return fmt.Errorf("%w: %s value %s is not a number",
					ErrHeaderRangeMalformed, name, headerRange)
			}
		case 2: //nolint:mnd
			for _, field := range fields {
				_, err := strconv.Atoi(field)
				if err != nil {
					return fmt.Errorf("%w: %s value %s is not a valid range",
						ErrHeaderRangeMalformed, name, headerRange)
				}
			}
		default:
			return fmt.Errorf("%w: %s value %s must be in the form n or n-m",
				ErrHeaderRangeMalformed, name, headerRange)
		}
	}

	return nil
}
