package updater

import (
	"fmt"
	"strings"
)

func parseFilename(fileName string) (
	region string, err error,
) {
	const suffix = ".ovpn"
	if !strings.HasSuffix(fileName, suffix) {
		return "", fmt.Errorf("filename does not have the openvpn file extension: %s", fileName)
	}

	region = strings.TrimSuffix(fileName, suffix)
	region = strings.ReplaceAll(region, " - ", " ")
	return region, nil
}
