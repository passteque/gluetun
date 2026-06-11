package pkcs8

import (
	"encoding/base64"
	"fmt"

	pkcs8lib "github.com/youmark/pkcs8"
)

// UpgradeEncryptedKey eventually upgrades an encrypted key to a newer encryption
// if its encryption is too weak for Openvpn/Openssl.
// If the key is encrypted using DES-CBC, it is decrypted and re-encrypted using AES-256-CBC.
// Otherwise, the key is returned unmodified.
// Note this function only supports:
// - PKCS8 encrypted keys
// - RSA and ECDSA keys
// - DES-CBC, 3DES, AES-128-CBC, AES-192-CBC, AES-256-CBC, AES-128-GCM, AES-192-GCM
// and AES-256-GCM encryption algorithms.
func UpgradeEncryptedKey(encryptedPKCS8DERKey, passphrase string) (securelyEncryptedPKCS8DERKey string, err error) {
	der, err := base64.StdEncoding.DecodeString(encryptedPKCS8DERKey)
	if err != nil {
		return "", fmt.Errorf("decoding base64 encoded DER: %w", err)
	}

	oidEncryptionAlgorithm, err := getEncryptionAlgorithmOid(der)
	if err != nil {
		return "", fmt.Errorf("finding encryption algorithm oid: %w", err)
	}

	if !oidEncryptionAlgorithm.Equal(oidDESCBC) {
		return encryptedPKCS8DERKey, nil
	}

	// Convert DES-CBC encrypted key to an AES256CBC encrypted key
	privateKey, err := pkcs8lib.ParsePKCS8PrivateKey(der, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("parsing pkcs8 encrypted private key: %w", err)
	}

	der, err = pkcs8lib.MarshalPrivateKey(privateKey, []byte(passphrase), pkcs8lib.DefaultOpts)
	if err != nil {
		return "", fmt.Errorf("encrypting and encoding private key: %w", err)
	}

	securelyEncryptedPKCS8DERKey = base64.StdEncoding.EncodeToString(der)
	return securelyEncryptedPKCS8DERKey, nil
}
