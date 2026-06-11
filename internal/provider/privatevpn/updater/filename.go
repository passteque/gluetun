package updater

import (
	"fmt"
	"regexp"
	"strings"
)

var trailingNumber = regexp.MustCompile(` [0-9]+$`)

func parseFilename(fileName string) (
	countryCode, city string, err error,
) {
	fileName = strings.ReplaceAll(fileName, " ", "") // remove spaces

	const prefix = "PrivateVPN-"
	if !strings.HasPrefix(fileName, prefix) {
		return "", "", fmt.Errorf("bad prefix in file name %s", fileName)
	}
	s := strings.TrimPrefix(fileName, prefix)

	const tcpSuffix = "-TUN-443.ovpn"
	const udpSuffix = "-TUN-1194.ovpn"
	switch {
	case strings.HasSuffix(fileName, tcpSuffix):
		s = strings.TrimSuffix(s, tcpSuffix)
	case strings.HasSuffix(fileName, udpSuffix):
		s = strings.TrimSuffix(s, udpSuffix)
	default:
		return "", "", fmt.Errorf("bad suffix in file name %s", fileName)
	}

	s = trailingNumber.ReplaceAllString(s, "")

	parts := strings.Split(s, "-")
	const minParts = 2
	if len(parts) < minParts {
		return "", "", fmt.Errorf("not enough parts in file name %s", fileName)
	}
	countryCode, city = parts[0], parts[1]

	countryCode = strings.ToLower(countryCode)
	if countryCode == "co" && strings.HasPrefix(city, "Bogot") {
		city = "Bogota"
	}

	return countryCode, city, nil
}
