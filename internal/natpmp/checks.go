package natpmp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func checkRequest(request []byte) (err error) {
	const minMessageSize = 2 // version number + operation code
	if len(request) < minMessageSize {
		return fmt.Errorf("message size is too small: need at least %d bytes and got %d byte(s)",
			minMessageSize, len(request))
	}

	return nil
}

func checkResponse(response []byte, expectedOperationCode byte,
	expectedResponseSize uint,
) (err error) {
	const minResponseSize = 4
	if len(response) < minResponseSize {
		return fmt.Errorf("response size is too small: "+
			"need at least %d bytes and got %d byte(s)",
			minResponseSize, len(response))
	}

	if uint(len(response)) != expectedResponseSize {
		return fmt.Errorf("response size is unexpected: "+
			"expected %d bytes and got %d byte(s)",
			expectedResponseSize, len(response))
	}

	protocolVersion := response[0]
	if protocolVersion != 0 {
		return fmt.Errorf("protocol version is unknown: %d", protocolVersion)
	}

	operationCode := response[1]
	if operationCode != expectedOperationCode {
		return fmt.Errorf("operation code is unexpected: expected 0x%x and got 0x%x", expectedOperationCode, operationCode)
	}

	resultCode := binary.BigEndian.Uint16(response[2:4])
	err = checkResultCode(resultCode)
	if err != nil {
		return fmt.Errorf("result code: %w", err)
	}

	return nil
}

// checkResultCode checks the result code and returns an error
// if the result code is not a success (0).
// See https://www.ietf.org/rfc/rfc6886.html#section-3.5
//
//nolint:mnd
func checkResultCode(resultCode uint16) (err error) {
	switch resultCode {
	case 0:
		return nil
	case 1:
		return errors.New("version is not supported")
	case 2:
		return errors.New("not authorized")
	case 3:
		return errors.New("network failure")
	case 4:
		return errors.New("out of resources")
	case 5:
		return errors.New("operation code is not supported")
	default:
		return fmt.Errorf("result code is unknown: %d", resultCode)
	}
}
