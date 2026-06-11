package extract

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/models"
)

// Data extracts the lines and connection from the OpenVPN configuration file.
func (e *Extractor) Data(filepath string) (lines []string,
	connection models.Connection, err error,
) {
	lines, err = readCustomConfigLines(filepath)
	if err != nil {
		return nil, connection, fmt.Errorf("reading configuration file: %w", err)
	}

	connection, err = extractDataFromLines(lines)
	if err != nil {
		return nil, connection, fmt.Errorf("extracting connection from file: %w", err)
	}

	return lines, connection, nil
}
