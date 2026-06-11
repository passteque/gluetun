package updater

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrNoIDInServerName = errors.New("no ID in server name")

func parseServerName(serverName string) (number uint16, err error) {
	i := strings.IndexRune(serverName, '#')
	if i < 0 {
		return 0, fmt.Errorf("%w: %s", ErrNoIDInServerName, serverName)
	}

	idString := serverName[i+1:]
	idUint64, err := strconv.ParseUint(idString, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid ID in server name: %s", serverName)
	}

	number = uint16(idUint64)
	return number, nil
}
