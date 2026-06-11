package service

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func portsToString(ports []uint16) (s string) {
	switch len(ports) {
	case 0:
		return "no port forwarded"
	case 1:
		return "port forwarded is " + fmt.Sprint(int(ports[0]))
	default:
		portStrings := make([]string, len(ports))
		for i, port := range ports {
			portStrings[i] = fmt.Sprint(int(port))
		}
		return "ports forwarded are " + strings.Join(portStrings[:len(portStrings)-1], ", ") +
			" and " + portStrings[len(portStrings)-1]
	}
}

func portPairsToString(internalToExternalPort map[uint16]uint16) (s string) {
	switch len(internalToExternalPort) {
	case 0:
		return "no port forwarded"
	case 1:
		internal := slices.Collect(maps.Keys(internalToExternalPort))[0]
		return "port forwarded is " + portPairToString(internal, internalToExternalPort[internal])
	default:
		portStrings := make([]string, 0, len(internalToExternalPort))
		for internal, external := range internalToExternalPort {
			portStrings = append(portStrings, portPairToString(internal, external))
		}
		sort.StringSlice(portStrings).Sort()
		return "ports forwarded are " + strings.Join(portStrings[:len(portStrings)-1], ", ") +
			" and " + portStrings[len(portStrings)-1]
	}
}

func portPairToString(internal, external uint16) string {
	if internal == external {
		return strconv.FormatUint(uint64(external), 10)
	}
	return fmt.Sprintf("%d (internal port %d)", external, internal)
}
