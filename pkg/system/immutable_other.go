//go:build !linux

package system

import "errors"

// SetImmutable is unsupported on non-Linux platforms (the immutable inode flag
// is a Linux filesystem feature). netop is a Linux tool; this stub exists only
// so the package cross-compiles for the darwin CI build.
func SetImmutable(path string, immutable bool) error {
	return errors.New("setting the immutable flag is only supported on Linux")
}
