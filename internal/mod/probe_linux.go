package mod

import (
	"errors"
	"fmt"
)

// Probe is a expanded version of modprobe, in which it checks if the Kernel
// built-in features contain the given module name.
// It first tries to locate the modules directory in [getModulesPath].
// If it fails (like on WSL), it then only checks for the kernel feature
// in /proc/config.gz with [checkProcConfig].
// Otherwise, it then runs the classic [modProbe] behavior,
// trying to load the module in the kernel.
// If this fails, it does one final try running [checkProcConfig].
func Probe(moduleName string) error {
	modulesPath, err := getModulesPath()
	if err != nil {
		if errors.Is(err, ErrModulesDirectoryNotFound) {
			err = checkProcConfig(moduleName)
			if err != nil {
				return fmt.Errorf("checking /proc/config.gz: %w", err)
			}
			return nil
		}
		return fmt.Errorf("getting modules path: %w", err)
	}

	err = modProbe(modulesPath, moduleName)
	if err != nil {
		err = checkProcConfig(moduleName)
		if err != nil {
			return fmt.Errorf("checking /proc/config.gz: %w", err)
		}
	}
	return nil
}

// modProbe is the classic modprobe behavior.
func modProbe(modulesPath, moduleName string) error {
	modulesInfo, err := getModulesInfo(modulesPath)
	if err != nil {
		return fmt.Errorf("getting modules information: %w", err)
	}

	modulePath, err := findModulePath(moduleName, modulesInfo)
	if err != nil {
		return fmt.Errorf("finding module path: %w", err)
	}

	info := modulesInfo[modulePath]
	if info.state == builtin || info.state == loaded {
		return nil
	}

	info.state = loading
	for _, dependencyModulePath := range info.dependencyPaths {
		err = initDependencies(dependencyModulePath, modulesInfo)
		if err != nil {
			return fmt.Errorf("init dependencies: %w", err)
		}
	}

	err = initModule(modulePath)
	if err != nil {
		return fmt.Errorf("init module: %w", err)
	}
	return nil
}
