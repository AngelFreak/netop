package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// DefaultDir returns the tunnel state directory. Tunnels belong to the user
// who runs ssh, not to root, so this never uses /run/net: under sudo it is
// the calling user's directory, and the same one net uses after dropping to
// that user.
func DefaultDir() string {
	uid, viaSudo := OwnerUID()
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if viaSudo {
		xdg = "" // sudo's environment, not the user's
	}
	return dirFor(uid, xdg, isDir)
}

// OwnerUID is the user whose tunnels net manages: the sudo caller when net
// runs as root under sudo, otherwise the current user.
func OwnerUID() (uid int, viaSudo bool) {
	if os.Geteuid() == 0 {
		if id, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil && id > 0 {
			return id, true
		}
	}
	return os.Geteuid(), false
}

// dirFor picks the state directory: the user's runtime dir when known, else
// /run/user/<uid>, else a per-user directory in /tmp.
func dirFor(uid int, xdgRuntimeDir string, exists func(string) bool) string {
	if xdgRuntimeDir != "" {
		return filepath.Join(xdgRuntimeDir, "net", "tunnels")
	}
	if runUser := fmt.Sprintf("/run/user/%d", uid); exists(runUser) {
		return filepath.Join(runUser, "net", "tunnels")
	}
	return filepath.Join("/tmp", fmt.Sprintf("net-%d", uid), "tunnels")
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// ensureDir creates dir and checks that it and its parent, the two levels
// net creates, are real directories private to the current user. In /tmp
// another user could otherwise pre-create them and swap the control sockets.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating tunnel directory: %w", err)
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := checkPrivateDir(d); err != nil {
			return err
		}
	}
	return nil
}

func checkPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("checking tunnel directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("tunnel directory %s must be a directory, not a symlink or file", dir)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return fmt.Errorf("tunnel directory %s must be private (mode 0700), it is %#o", dir, perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("tunnel directory %s is owned by uid %d, not you (uid %d)", dir, st.Uid, os.Geteuid())
	}
	return nil
}
