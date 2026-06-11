package pkcs8

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Algorithm identifiers are listed at
// https://www.ibm.com/docs/en/zos/2.3.0?topic=programming-object-identifiers
var oidDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7} //nolint:gochecknoglobals

type encryptedPrivateKey struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type encryptedAlgorithmParams struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

func getEncryptionAlgorithmOid(der []byte) (
	encryptionSchemeAlgorithm asn1.ObjectIdentifier, err error,
) {
	var encryptedPrivateKeyData encryptedPrivateKey
	_, err = asn1.Unmarshal(der, &encryptedPrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("decoding asn1 encrypted private key data: %w", err)
	}

	oidPBES2 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidAlgorithm := encryptedPrivateKeyData.EncryptionAlgorithm.Algorithm
	if !oidAlgorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("encryption algorithm is not PBES2: %s instead of PBES2 %s",
			oidAlgorithm, oidPBES2)
	}

	var encryptionAlgorithmParams encryptedAlgorithmParams
	paramBytes := encryptedPrivateKeyData.EncryptionAlgorithm.Parameters.FullBytes
	_, err = asn1.Unmarshal(paramBytes, &encryptionAlgorithmParams)
	if err != nil {
		return nil, fmt.Errorf("decoding asn1 encryption algorithm parameters: %w", err)
	}

	return encryptionAlgorithmParams.EncryptionScheme.Algorithm, nil
}
