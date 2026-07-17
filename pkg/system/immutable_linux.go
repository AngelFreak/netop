//go:build linux

package system

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// fsImmutableFL is the FS_IMMUTABLE_FL inode flag from <linux/fs.h>. It is not
// exported by golang.org/x/sys/unix, so we define it here. Setting it makes a
// file immutable (equivalent to `chattr +i`).
const fsImmutableFL = 0x00000010

// SetImmutable sets or clears the immutable inode flag on path, natively via the
// FS_IOC_GETFLAGS/FS_IOC_SETFLAGS ioctls (replacing `chattr +i/-i`). It reads
// the current flags, toggles only the immutable bit, and writes them back so
// other inode flags are preserved.
func SetImmutable(path string, immutable bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening %q: %w", path, err)
	}
	defer unix.Close(fd)

	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return fmt.Errorf("reading inode flags on %q: %w", path, err)
	}

	newFlags := flags
	if immutable {
		newFlags |= fsImmutableFL
	} else {
		newFlags &^= fsImmutableFL
	}
	if newFlags == flags {
		return nil // already in the desired state
	}

	if err := unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, newFlags); err != nil {
		return fmt.Errorf("setting inode flags on %q: %w", path, err)
	}
	return nil
}
