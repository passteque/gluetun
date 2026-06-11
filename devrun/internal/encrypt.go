package internal

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// Encryption format: [16-byte salt][12-byte nonce][AES-256-GCM ciphertext+tag]
// Key derivation: scrypt(password, salt, N=32768, r=8, p=1, keyLen=32)

const (
	saltSize  = 16
	nonceSize = 12
	keySize   = 32
	scryptN   = 32768
	scryptR   = 8
	scryptP   = 1
)

// AddCredential prompts for credential values and stores them in the encrypted credentials file.
func AddCredential(ctx context.Context, provider, vpnType string) error {
	credentials, password, err := loadCredentialsForMutation(ctx)
	if err != nil {
		return err
	}

	err = promptAndAddCredential(ctx, credentials, provider, vpnType)
	if err != nil {
		return err
	}

	err = validateCredentials(credentials)
	if err != nil {
		return fmt.Errorf("validating credentials: %w", err)
	}

	err = writeEncryptedCredentials(credentials, password)
	if err != nil {
		return err
	}

	fmt.Printf(
		"Credentials for provider %q and vpn type %q saved to %s\n",
		provider, vpnType, credentialsFilename,
	)
	return nil
}

// DeleteCredential removes credentials for a provider and VPN type
// from the encrypted credentials file.
func DeleteCredential(ctx context.Context, provider, vpnType string) error {
	credentials, password, err := loadExistingCredentialsForMutation(ctx)
	if err != nil {
		return err
	}

	err = deleteCredential(credentials, provider, vpnType)
	if err != nil {
		return err
	}

	err = writeEncryptedCredentials(credentials, password)
	if err != nil {
		return err
	}

	fmt.Printf(
		"Credentials for provider %q and vpn type %q removed from %s\n",
		provider, vpnType, credentialsFilename,
	)
	return nil
}

// DumpCredential decrypts the credential store and prints one provider/vpn-type entry.
func DumpCredential(ctx context.Context, provider, vpnType string) error {
	credentials, err := decryptCredentials(ctx)
	if err != nil {
		return err
	}

	providerCredentials, exists := credentials[provider]
	if !exists {
		existingProviders := slices.Collect(maps.Keys(credentials))
		return fmt.Errorf("provider %q does not exist, available providers are: %s",
			provider, strings.Join(existingProviders, ", "))
	}

	output, err := formatCredentialForDump(provider, vpnType, providerCredentials)
	if err != nil {
		return err
	}

	fmt.Println(output)
	return nil
}

// decryptCredentials reads the encrypted credentials file,
// prompts for a password, and returns the decrypted credentials.
func decryptCredentials(ctx context.Context) (map[string]providerCredentials, error) {
	password, err := readSecret(ctx, "Enter credentials password: ", false)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}

	plaintext, err := decryptCredentialsFile(password)
	if err != nil {
		return nil, err
	}

	credentials, err := loadCredentials(plaintext)
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}

	return credentials, nil
}

func loadCredentialsForMutation(ctx context.Context) (
	credentials map[string]providerCredentials,
	password []byte,
	err error,
) {
	_, err = os.Stat(credentialsFilename)
	if os.IsNotExist(err) {
		password, err = readPasswordConfirmed(ctx,
			"Enter new credentials password: ",
			"Confirm new credentials password: ",
		)
		if err != nil {
			return nil, nil, fmt.Errorf("reading password: %w", err)
		}
		return make(map[string]providerCredentials), password, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stating %s: %w", credentialsFilename, err)
	}

	password, err = readSecret(ctx, "Enter credentials password: ", false)
	if err != nil {
		return nil, nil, fmt.Errorf("reading password: %w", err)
	}

	plaintext, err := decryptCredentialsFile(password)
	if err != nil {
		return nil, nil, err
	}

	credentials, err = loadCredentials(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("loading credentials: %w", err)
	}

	return credentials, password, nil
}

func loadExistingCredentialsForMutation(ctx context.Context) (
	credentials map[string]providerCredentials,
	password []byte,
	err error,
) {
	_, err = os.Stat(credentialsFilename)
	if os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("%s does not exist", credentialsFilename)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("stating %s: %w", credentialsFilename, err)
	}

	password, err = readSecret(ctx, "Enter credentials password: ", false)
	if err != nil {
		return nil, nil, fmt.Errorf("reading password: %w", err)
	}

	plaintext, err := decryptCredentialsFile(password)
	if err != nil {
		return nil, nil, err
	}

	credentials, err = loadCredentials(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("loading credentials: %w", err)
	}

	return credentials, password, nil
}

func promptAndAddCredential(
	ctx context.Context,
	credentials map[string]providerCredentials,
	provider, vpnType string,
) error {
	switch vpnType {
	case vpnTypeOpenVPN:
		username, err := readLine(ctx, "OpenVPN username: ", true)
		if err != nil {
			return fmt.Errorf("reading username: %w", err)
		}

		password, err := readSecret(ctx, "OpenVPN password: ", username == "")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}

		key, err := readSecret(ctx, "OpenVPN key: ", true)
		if err != nil {
			return fmt.Errorf("reading key: %w", err)
		}

		cert, err := readSecret(ctx, "OpenVPN cert: ", true)
		if err != nil {
			return fmt.Errorf("reading cert: %w", err)
		}

		openvpnCredentials := &openvpnCredentials{
			Username: username,
			Password: string(password),
			Key:      string(key),
			Cert:     string(cert),
		}
		err = validateOpenvpnCredentials(provider, openvpnCredentials)
		if err != nil {
			return err
		}

		return addCredential(credentials, provider, vpnType, openvpnCredentials, nil)

	case vpnTypeWireGuard:
		privateKey, err := readSecret(ctx, "WireGuard private key: ", false)
		if err != nil {
			return fmt.Errorf("reading private key: %w", err)
		}

		address, err := readLine(ctx, "WireGuard address (optional): ", true)
		if err != nil {
			return fmt.Errorf("reading address: %w", err)
		}

		presharedKey, err := readSecret(
			ctx,
			"WireGuard preshared key (optional): ",
			true,
		)
		if err != nil {
			return fmt.Errorf("reading preshared key: %w", err)
		}

		wireguardCredentials := &wireguardCredentials{
			PrivateKey:   string(privateKey),
			Address:      address,
			PresharedKey: string(presharedKey),
		}
		err = validateWireguardCredentials(provider, wireguardCredentials)
		if err != nil {
			return err
		}

		return addCredential(credentials, provider, vpnType, nil, wireguardCredentials)

	default:
		return fmt.Errorf("unknown vpn type %q, must be wireguard or openvpn", vpnType)
	}
}

func writeEncryptedCredentials(
	credentials map[string]providerCredentials,
	password []byte,
) error {
	plaintext, err := marshalCredentials(credentials)
	if err != nil {
		return fmt.Errorf("encoding credentials: %w", err)
	}

	encrypted, err := encryptData(plaintext, password)
	if err != nil {
		return fmt.Errorf("encrypting credentials: %w", err)
	}

	const filePerms = 0o600
	err = os.WriteFile(credentialsFilename, encrypted, filePerms)
	if err != nil {
		return fmt.Errorf("writing %s: %w", credentialsFilename, err)
	}

	return nil
}

func decryptCredentialsFile(password []byte) ([]byte, error) {
	encryptedData, err := os.ReadFile(credentialsFilename)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", credentialsFilename, err)
	}

	plaintext, err := decryptData(encryptedData, password)
	if err != nil {
		return nil, fmt.Errorf("decrypting credentials: %w", err)
	}

	return plaintext, nil
}

func readSecret(ctx context.Context, prompt string, allowEmpty bool) ([]byte, error) {
	fmt.Print(prompt)

	passwordFD, err := syscall.Dup(syscall.Stdin)
	if err != nil {
		fmt.Println()
		return nil, fmt.Errorf("duplicating stdin file descriptor: %w", err)
	}

	var closeFDOnce sync.Once
	closePasswordFD := func() {
		closeFDOnce.Do(func() {
			_ = syscall.Close(passwordFD)
		})
	}

	passwordResult := make(chan struct {
		password []byte
		err      error
	})

	go func() {
		password, err := term.ReadPassword(passwordFD)
		closePasswordFD()
		result := struct {
			password []byte
			err      error
		}{
			password: password,
			err:      err,
		}

		select {
		case <-ctx.Done():
			return
		case passwordResult <- result:
		}
	}()

	select {
	case <-ctx.Done():
		closePasswordFD()
		fmt.Println()
		return nil, ctx.Err()
	case result := <-passwordResult:
		closePasswordFD()
		fmt.Println()
		if result.err != nil {
			return nil, fmt.Errorf("reading hidden input from terminal: %w", result.err)
		}
		if len(result.password) == 0 && !allowEmpty {
			return nil, fmt.Errorf("value cannot be empty")
		}
		return result.password, nil
	}
}

func readLine(ctx context.Context, prompt string, allowEmpty bool) (string, error) {
	fmt.Print(prompt)

	inputFD, err := syscall.Dup(syscall.Stdin)
	if err != nil {
		fmt.Println()
		return "", fmt.Errorf("duplicating stdin file descriptor: %w", err)
	}

	var closeFDOnce sync.Once
	closeInputFD := func() {
		closeFDOnce.Do(func() {
			_ = syscall.Close(inputFD)
		})
	}

	inputResult := make(chan struct {
		value string
		err   error
	})

	go func() {
		inputFile := os.NewFile(uintptr(inputFD), "stdin")
		reader := bufio.NewReader(inputFile)
		value, err := reader.ReadString('\n')
		closeInputFD()
		value = strings.TrimRight(value, "\r\n")
		if err == io.EOF {
			err = nil
		}

		result := struct {
			value string
			err   error
		}{
			value: value,
			err:   err,
		}

		select {
		case <-ctx.Done():
			return
		case inputResult <- result:
		}
	}()

	select {
	case <-ctx.Done():
		closeInputFD()
		fmt.Println()
		return "", ctx.Err()
	case result := <-inputResult:
		closeInputFD()
		if result.err != nil {
			return "", fmt.Errorf("reading line from terminal: %w", result.err)
		}
		if result.value == "" && !allowEmpty {
			return "", fmt.Errorf("value cannot be empty")
		}
		return result.value, nil
	}
}

func readPasswordConfirmed(
	ctx context.Context,
	prompt, confirmationPrompt string,
) ([]byte, error) {
	password, err := readSecret(ctx, prompt, false)
	if err != nil {
		return nil, err
	}

	confirmation, err := readSecret(ctx, confirmationPrompt, false)
	if err != nil {
		return nil, err
	}

	if string(password) != string(confirmation) {
		return nil, fmt.Errorf("passwords do not match")
	}

	return password, nil
}

func deriveKey(password, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("deriving key with scrypt: %w", err)
	}
	return key, nil
}

func encryptData(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, 0, saltSize+nonceSize+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

func decryptData(data, password []byte) ([]byte, error) {
	const minSize = saltSize + nonceSize + 16 // 16 is the GCM tag size
	if len(data) < minSize {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(data))
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting data (wrong password?): %w", err)
	}

	return plaintext, nil
}
