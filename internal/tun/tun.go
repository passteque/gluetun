//go:build linux || darwin

package tun

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func Setup() error {
	const tunDevice = "/dev/net/tun"
	err := check(tunDevice)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		err = create(tunDevice)
		if err != nil {
			return fmt.Errorf("creating TUN device: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("checking TUN device: %w (see the Wiki errors/tun page)", err)
	}
}

// check checks the tunnel device specified by path is present and accessible.
func check(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("TUN device is not available: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("getting stat information for TUN file: %w", err)
	}

	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot get syscall stat info of TUN file")
	}

	const expectedRdev = 2760 // corresponds to major 10 and minor 200
	if sys.Rdev != expectedRdev {
		return fmt.Errorf("TUN file has an unexpected rdev: %d instead of expected %d",
			sys.Rdev, expectedRdev)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("closing TUN device: %w", err)
	}

	return nil
}

// create creates a TUN device at the path specified.
func create(path string) (err error) {
	parentDir := filepath.Dir(path)
	err = os.MkdirAll(parentDir, 0o751) //nolint:mnd
	if err != nil {
		return err
	}

	const (
		major = 10
		minor = 200
	)
	dev := unix.Mkdev(major, minor)
	if dev > math.MaxInt {
		panic("dev is too high")
	}
	err = unix.Mknod(path, unix.S_IFCHR, int(dev))
	if err != nil {
		return fmt.Errorf("creating TUN device file node: %w", err)
	}

	fd, err := unix.Open(path, 0, 0)
	if err != nil {
		if err.Error() == "operation not permitted" {
			err = fmt.Errorf("%w (did you specify --device /dev/net/tun to your container command?)", err)
		}
		return fmt.Errorf("unix opening TUN device file: %w", err)
	}

	const nonBlocking = true
	err = unix.SetNonblock(fd, nonBlocking)
	if err != nil {
		return fmt.Errorf("setting non block to TUN device file descriptor: %w", err)
	}

	return nil
}
