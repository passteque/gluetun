package mod

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

func initDependencies(path string, modulesInfo map[string]moduleInfo) (err error) {
	info, ok := modulesInfo[path]
	if !ok {
		return fmt.Errorf("module info not found: %s", path)
	}

	switch info.state {
	case unloaded:
	case loaded, builtin:
		return nil
	case loading:
		return fmt.Errorf("circular dependency: %s is already in the loading state", path)
	}

	info.state = loading
	modulesInfo[path] = info

	for _, dependencyPath := range info.dependencyPaths {
		err = initDependencies(dependencyPath, modulesInfo)
		if err != nil {
			return fmt.Errorf("init dependencies for %s: %w", path, err)
		}
	}

	err = initModule(path)
	if err != nil {
		return fmt.Errorf("loading module: %w", err)
	}
	info.state = loaded
	modulesInfo[path] = info

	return nil
}

func initModule(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening module file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	var reader io.Reader
	switch filepath.Ext(file.Name()) {
	case ".xz":
		reader, err = xz.NewReader(file)
	case ".gz":
		reader, err = pgzip.NewReader(file)
	case ".zst":
		reader, err = zstd.NewReader(file)
	default:
		const moduleParams = ""
		const flags = 0
		err = unix.FinitModule(int(file.Fd()), moduleParams, flags)
		switch {
		case err == nil, err == unix.EEXIST: //nolint:err113
			return nil
		case err != unix.ENOSYS: //nolint:err113
			if strings.HasSuffix(err.Error(), "operation not permitted") {
				err = fmt.Errorf("%w; did you set the SYS_MODULE capability to your container?", err)
			}
			return fmt.Errorf("finit module %s: %w", path, err)
		case flags != 0:
			return err // unix.ENOSYS error
		default: // Fall back to init_module(2).
			reader = file
		}
	}

	if err != nil {
		return fmt.Errorf("reading from %s: %w", path, err)
	}

	image, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading module image from %s: %w", path, err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing module file %s: %w", path, err)
	}

	const params = ""
	err = unix.InitModule(image, params)
	switch err {
	case nil, unix.EEXIST:
		return nil
	default:
		return fmt.Errorf("init module read from %s: %w", path, err)
	}
}
