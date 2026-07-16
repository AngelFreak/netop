//go:build integration && linux

package system

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetImmutableRoundTrip sets and clears the immutable flag on a real file
// and verifies the flag actually changed (requires CAP_LINUX_IMMUTABLE / root).
func TestSetImmutableRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: setting the immutable flag requires root")
	}

	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	readFlags := func() int {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer unix.Close(fd)
		flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
		if err != nil {
			t.Fatalf("GETFLAGS: %v", err)
		}
		return flags
	}

	// Set immutable, then confirm the bit is set.
	if err := SetImmutable(path, true); err != nil {
		t.Fatalf("SetImmutable(true): %v", err)
	}
	if readFlags()&fsImmutableFL == 0 {
		t.Errorf("immutable flag not set after SetImmutable(true)")
	}

	// A locked file cannot be written or removed.
	if err := os.WriteFile(path, []byte("nameserver 8.8.8.8\n"), 0644); err == nil {
		t.Errorf("write to immutable file unexpectedly succeeded")
	}

	// Clear immutable, then confirm the bit is cleared and the file is writable.
	if err := SetImmutable(path, false); err != nil {
		t.Fatalf("SetImmutable(false): %v", err)
	}
	if readFlags()&fsImmutableFL != 0 {
		t.Errorf("immutable flag still set after SetImmutable(false)")
	}
	if err := os.WriteFile(path, []byte("nameserver 8.8.8.8\n"), 0644); err != nil {
		t.Errorf("write after clearing immutable failed: %v", err)
	}
}
