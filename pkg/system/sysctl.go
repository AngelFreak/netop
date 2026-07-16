package system

import (
	"fmt"
	"os"
	"strings"
)

// ipForwardPath is the sysctl file controlling IPv4 forwarding. It is a package
// variable so tests can point it at a temporary file via SetIPForwardPathForTest.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// SetIPForwardPathForTest overrides the ip_forward sysctl path and returns a
// function that restores the original. Intended for use by tests in other
// packages (hotspot, dhcp) that exercise NAT setup without touching the real
// /proc sysctl.
func SetIPForwardPathForTest(path string) (restore func()) {
	prev := ipForwardPath
	ipForwardPath = path
	return func() { ipForwardPath = prev }
}

// ReadIPForward returns the current IPv4 forwarding setting ("0" or "1"), or an
// error if the sysctl file cannot be read. Replaces `cat /proc/.../ip_forward`.
func ReadIPForward() (string, error) {
	data, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return "", fmt.Errorf("reading ip_forward: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteIPForward sets the IPv4 forwarding sysctl to value ("0" or "1"). Replaces
// `sh -c "echo N > /proc/.../ip_forward"`. The sysctl accepts a bare value with
// no trailing newline.
func WriteIPForward(value string) error {
	if value != "0" && value != "1" {
		return fmt.Errorf("invalid ip_forward value %q: must be \"0\" or \"1\"", value)
	}
	// 0644 matches the existing sysctl file mode; WriteFile won't chmod an
	// existing file, so this only applies if the path is newly created (tests).
	if err := os.WriteFile(ipForwardPath, []byte(value), 0644); err != nil {
		return fmt.Errorf("writing ip_forward: %w", err)
	}
	return nil
}
