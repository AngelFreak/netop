package system

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/angelfreak/net/pkg/types"
)

// SanitizeForTerminal makes an untrusted string safe to print to a terminal by
// replacing control characters (ANSI escapes, backspaces, etc.) with '?'. This
// prevents terminal-escape injection from attacker-controlled values such as
// scanned SSIDs (over-the-air) and DHCP lease hostnames (from LAN clients).
// Ordinary printable characters, including spaces, are left unchanged.
func SanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// KillProcessFast kills processes immediately with SIGKILL (for daemons where graceful shutdown isn't needed).
// This is faster than graceful shutdown (~200-500ms saved) and appropriate for network daemons
// like wpa_supplicant, dhclient, etc. where state cleanup isn't critical.
func KillProcessFast(executor types.SystemExecutor, logger types.Logger, pattern string) {
	_, err := executor.ExecuteWithTimeout(500*time.Millisecond, "pkill", "-9", "-f", pattern)
	if err != nil {
		logger.Debug("No process to kill or pkill failed", "pattern", pattern)
	}
}

// KillProcessGraceful tries SIGTERM first, then SIGKILL after 200ms if still running.
// Use this for processes that benefit from graceful shutdown (e.g., VPN daemons that need
// to clean up connections or save state).
func KillProcessGraceful(executor types.SystemExecutor, logger types.Logger, pattern string) {
	// First try graceful shutdown (SIGTERM) with 1s timeout
	_, err := executor.ExecuteWithTimeout(1*time.Second, "pkill", "-f", pattern)
	if err != nil {
		logger.Debug("No process to kill or pkill failed", "pattern", pattern)
		return
	}

	// Wait briefly for graceful shutdown
	time.Sleep(200 * time.Millisecond)

	// Check if process is still running, if so force kill with SIGKILL
	_, err = executor.ExecuteWithTimeout(1*time.Second, "pgrep", "-f", pattern)
	if err == nil {
		// Process still running, force kill
		logger.Debug("Process still running, sending SIGKILL", "pattern", pattern)
		_, _ = executor.ExecuteWithTimeout(1*time.Second, "pkill", "-9", "-f", pattern)
	}
}

// WriteSecureFile writes content to a file with 0600 permissions atomically.
// It writes to a temporary file in the same directory, chmods it to 0600, then
// renames it over the destination — so the file never appears with wrong
// permissions (TOCTOU avoidance), matching the semantics of `install -m 0600`.
// Native replacement for shelling out to `install`.
func WriteSecureFile(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".net-secure-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we don't successfully rename into place.
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	// Set 0600 before writing content so the secret never exists world-readable.
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming temp file to %q: %w", path, err)
	}
	tmpName = "" // renamed successfully; skip cleanup
	return nil
}

// ParseIPFromOutput extracts the first inet IP address from `ip addr show` output.
// Returns nil if no valid IP address is found.
func ParseIPFromOutput(output string) net.IP {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip, _, err := net.ParseCIDR(parts[1])
				if err == nil {
					return ip
				}
			}
		}
	}
	return nil
}

// ParseGatewayFromOutput extracts the default gateway from `ip route show` output.
// Returns nil if no default gateway is found.
func ParseGatewayFromOutput(output string) net.IP {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default via ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return net.ParseIP(parts[2])
			}
		}
	}
	return nil
}

// ParseDNSFromResolvConf extracts nameserver IPs from resolv.conf content.
// Returns an empty slice if no nameservers are found.
func ParseDNSFromResolvConf(content string) []net.IP {
	var dns []net.IP
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ipStr := strings.TrimPrefix(line, "nameserver ")
			if ip := net.ParseIP(ipStr); ip != nil {
				dns = append(dns, ip)
			}
		}
	}
	return dns
}

// ProcessAliveFromPIDFile reports whether the process whose PID is recorded in
// pidFile is currently alive, by probing it with signal 0 (native replacement
// for `cat <pidfile>` + `kill -0 <pid>`). It returns:
//   - (false, nil) if the pidfile is missing/empty/unparseable — treat as "no
//     tracked process", not an error.
//   - (true, nil)  if the process exists.
//   - (false, err) only when the pidfile held a valid PID and the liveness
//     probe reported the process is gone (ESRCH) or otherwise unreachable.
func ProcessAliveFromPIDFile(pidFile string) (bool, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false, nil
	}
	pidStr := strings.TrimSpace(string(data))
	if pidStr == "" {
		return false, nil
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return false, nil
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false, err
	}
	return true, nil
}

// KillProcessByPID kills a process by reading its PID from a file.
// Returns nil if successful or if the PID file doesn't exist.
// Uses SIGTERM first, then SIGKILL after a short delay if still running.
// Native: reads the pidfile and signals the process directly (no cat/kill/rm
// shell-outs).
func KillProcessByPID(logger types.Logger, pidFile string) error {
	// Read PID from file
	data, err := os.ReadFile(pidFile)
	if err != nil {
		logger.Debug("PID file not found or unreadable", "file", pidFile, "error", err)
		return nil // Not an error - process may not be running
	}

	pidStr := strings.TrimSpace(string(data))
	if pidStr == "" {
		logger.Debug("PID file is empty", "file", pidFile)
		return nil
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		logger.Debug("PID file does not contain a valid PID", "file", pidFile, "value", pidStr)
		return nil
	}

	// Try graceful shutdown first (SIGTERM)
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		logger.Debug("Process may already be dead", "pid", pid, "error", err)
		// Still clean up the stale pidfile before returning.
		_ = os.Remove(pidFile)
		return nil
	}

	// Wait briefly for graceful shutdown
	time.Sleep(200 * time.Millisecond)

	// Check if still running (signal 0 probes liveness without delivering a
	// signal) and force kill if necessary.
	if err := syscall.Kill(pid, 0); err == nil {
		// Process still running, send SIGKILL
		logger.Debug("Process still running after SIGTERM, sending SIGKILL", "pid", pid)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}

	// Clean up PID file
	_ = os.Remove(pidFile)

	return nil
}
