package socks5

import (
	"fmt"
	"io"
)

// See https://datatracker.ietf.org/doc/html/rfc1929#section-2
func usernamePasswordSubnegotiate(conn io.ReadWriter, username, password string) (err error) {
	status := byte(1)
	const defaultVersion = byte(1)

	const headerLength = 2
	var header [headerLength]byte
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		_, _ = conn.Write([]byte{defaultVersion, status})
		return fmt.Errorf("reading header: %w", err)
	}

	if header[0] != authUsernamePasswordSubNegotiation1 {
		_, _ = conn.Write([]byte{defaultVersion, status})
		return fmt.Errorf("subnegotiation version not supported: %d", header[0])
	}
	version := header[0]

	usernameBytes := make([]byte, header[1])
	_, err = io.ReadFull(conn, usernameBytes)
	if err != nil {
		_, _ = conn.Write([]byte{version, status})
		return fmt.Errorf("reading username bytes: %w", err)
	} else if username != string(usernameBytes) {
		_, _ = conn.Write([]byte{version, status})
		return fmt.Errorf("username received is not valid")
	}

	const passwordHeaderLength = 1
	passwordHeader := make([]byte, passwordHeaderLength)
	_, err = io.ReadFull(conn, passwordHeader)
	if err != nil {
		_, _ = conn.Write([]byte{version, status})
		return fmt.Errorf("reading password length: %w", err)
	}

	passwordBytes := make([]byte, passwordHeader[0])
	_, err = io.ReadFull(conn, passwordBytes)
	if err != nil {
		_, _ = conn.Write([]byte{version, status})
		return fmt.Errorf("reading password bytes: %w", err)
	} else if password != string(passwordBytes) {
		_, _ = conn.Write([]byte{version, status})
		return fmt.Errorf("password not valid for username %q", string(usernameBytes))
	}

	status = 0
	_, err = conn.Write([]byte{version, status})
	if err != nil {
		return fmt.Errorf("writing success status: %w", err)
	}

	return nil
}
