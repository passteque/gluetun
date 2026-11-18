package openvpn

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/qdm12/gluetun/internal/statusfile"
)

// WriteAuthFile writes the OpenVPN auth file to disk with the right permissions.
func (c *Configurator) WriteAuthFile(user, password string) error {
	content := strings.Join([]string{user, password}, "\n")
	return writeIfDifferent(c.authFilePath, content, c.puid)
}

// WriteAskPassFile writes the OpenVPN askpass file to disk with the right permissions.
func (c *Configurator) WriteAskPassFile(passphrase string) error {
	return writeIfDifferent(c.askPassPath, passphrase, c.puid)
}

// writeIfDifferent writes the file owned by puid and the process group with 0440:
// root reads it through its group without CAP_DAC_OVERRIDE, and puid as owner since
// OpenVPN reads it again with auth-nocache. It is recreated rather than written in
// place, since removing only needs write access to the root owned directory.
func writeIfDifferent(path, content string, puid int) error {
	const permission = fs.FileMode(0o440)
	gid := os.Getegid()
	if isUpToDate(path, content, permission, puid, gid) {
		return nil
	}

	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing file: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permission)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}

	_, err = file.WriteString(content)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("writing file: %w", err)
	}

	// chmod explicitly since OpenFile is subject to the umask
	err = file.Chmod(permission)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("setting file permissions: %w", err)
	}

	err = file.Chown(puid, gid)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("setting file ownership: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing file: %w", err)
	}
	return nil
}

func isUpToDate(path, content string, permission fs.FileMode, uid, gid int) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != permission || !statusfile.IsOwnedBy(info, uid, gid) {
		return false
	}

	existing, err := io.ReadAll(file)
	return err == nil && string(existing) == content
}
