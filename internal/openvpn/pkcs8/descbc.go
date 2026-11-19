package pkcs8

import (
	"bytes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec
	"encoding/asn1"
	"fmt"

	pkcs8lib "github.com/youmark/pkcs8"
)

func init() { //nolint:gochecknoinits
	pkcs8lib.RegisterCipher(oidDESCBC, newCipherDESCBCBlock)
}

func newCipherDESCBCBlock() pkcs8lib.Cipher {
	return cipherDESCBC{}
}

type cipherDESCBC struct{}

func (c cipherDESCBC) IVSize() int {
	return des.BlockSize
}

func (c cipherDESCBC) KeySize() int {
	return 8 //nolint:mnd
}

func (c cipherDESCBC) OID() asn1.ObjectIdentifier {
	return oidDESCBC
}

func (c cipherDESCBC) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("creating DES cipher: %w", err)
	}
	blockEncrypter := cipher.NewCBCEncrypter(block, iv)
	paddingLen := block.BlockSize() - (len(plaintext) % block.BlockSize())
	ciphertext := make([]byte, len(plaintext)+paddingLen)
	copy(ciphertext, plaintext)
	copy(ciphertext[len(plaintext):],
		bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)) //nolint:gosec
	blockEncrypter.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func (c cipherDESCBC) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("creating DES cipher: %w", err)
	}
	blockDecrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	blockDecrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}
