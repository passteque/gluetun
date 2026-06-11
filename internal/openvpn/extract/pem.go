package extract

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func PEM(b []byte) (encodedData string, err error) {
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		return "", errors.New("cannot decode PEM encoded block")
	}

	der := pemBlock.Bytes
	encodedData = base64.StdEncoding.EncodeToString(der)
	return encodedData, nil
}
