package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadWriteIPForward(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	restore := SetIPForwardPathForTest(path)
	defer restore()

	// Read the initial value (trailing newline trimmed).
	got, err := ReadIPForward()
	if err != nil {
		t.Fatalf("ReadIPForward: %v", err)
	}
	if got != "0" {
		t.Errorf("ReadIPForward = %q, want 0", got)
	}

	// Enable forwarding, then read it back.
	if err := WriteIPForward("1"); err != nil {
		t.Fatalf("WriteIPForward(1): %v", err)
	}
	got, err = ReadIPForward()
	if err != nil {
		t.Fatalf("ReadIPForward after write: %v", err)
	}
	if got != "1" {
		t.Errorf("after WriteIPForward(1), ReadIPForward = %q, want 1", got)
	}

	// The file content is the bare value, no trailing newline.
	data, _ := os.ReadFile(path)
	if string(data) != "1" {
		t.Errorf("file content = %q, want %q", string(data), "1")
	}
}

func TestWriteIPForward_RejectsInvalidValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_forward")
	restore := SetIPForwardPathForTest(path)
	defer restore()

	if err := WriteIPForward("2"); err == nil {
		t.Errorf("WriteIPForward(2): expected error, got nil")
	}
	if err := WriteIPForward(""); err == nil {
		t.Errorf("WriteIPForward(\"\"): expected error, got nil")
	}
	// Nothing should have been written.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("invalid write should not create the file")
	}
}

func TestReadIPForward_MissingFile(t *testing.T) {
	restore := SetIPForwardPathForTest(filepath.Join(t.TempDir(), "does-not-exist"))
	defer restore()

	if _, err := ReadIPForward(); err == nil {
		t.Errorf("ReadIPForward on missing file: expected error, got nil")
	}
}
