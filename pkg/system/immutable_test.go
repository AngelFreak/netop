//go:build linux

package system

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetImmutable_ClearIsNoOpWhenNotSet verifies that clearing the immutable
// flag on a file that isn't immutable is a no-op that succeeds without
// CAP_LINUX_IMMUTABLE (the GETFLAGS read is unprivileged and no SETFLAGS is
// issued when the flag is already clear).
func TestSetImmutable_ClearIsNoOpWhenNotSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := SetImmutable(path, false); err != nil {
		t.Errorf("clearing immutable on a non-immutable file should be a no-op, got: %v", err)
	}
}

// TestSetImmutable_MissingFile verifies a clear error (not a panic) when the
// path does not exist.
func TestSetImmutable_MissingFile(t *testing.T) {
	if err := SetImmutable(filepath.Join(t.TempDir(), "nope"), false); err == nil {
		t.Errorf("SetImmutable on missing file: expected error, got nil")
	}
}
