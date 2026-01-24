package system

import (
	"net"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

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
// Uses the install command to atomically create file with correct permissions,
// avoiding TOCTOU race where file exists briefly with wrong permissions.
func WriteSecureFile(executor types.SystemExecutor, path, content string) error {
	_, err := executor.ExecuteWithInput("install", content, "-m", "0600", "/dev/stdin", path)
	return err
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

// KillProcessByPID kills a process by reading its PID from a file.
// Returns nil if successful or if the PID file doesn't exist.
// Uses SIGTERM first, then SIGKILL after a short delay if still running.
func KillProcessByPID(executor types.SystemExecutor, logger types.Logger, pidFile string) error {
	// Read PID from file
	pid, err := executor.ExecuteWithTimeout(1*time.Second, "cat", pidFile)
	if err != nil {
		logger.Debug("PID file not found or unreadable", "file", pidFile, "error", err)
		return nil // Not an error - process may not be running
	}

	pid = strings.TrimSpace(pid)
	if pid == "" {
		logger.Debug("PID file is empty", "file", pidFile)
		return nil
	}

	// Try graceful shutdown first (SIGTERM)
	_, err = executor.ExecuteWithTimeout(1*time.Second, "kill", pid)
	if err != nil {
		logger.Debug("Process may already be dead", "pid", pid, "error", err)
		return nil
	}

	// Wait briefly for graceful shutdown
	time.Sleep(200 * time.Millisecond)

	// Check if still running and force kill if necessary
	_, err = executor.ExecuteWithTimeout(500*time.Millisecond, "kill", "-0", pid)
	if err == nil {
		// Process still running, send SIGKILL
		logger.Debug("Process still running after SIGTERM, sending SIGKILL", "pid", pid)
		_, _ = executor.ExecuteWithTimeout(1*time.Second, "kill", "-9", pid)
	}

	// Clean up PID file
	_, _ = executor.ExecuteWithTimeout(500*time.Millisecond, "rm", "-f", pidFile)

	return nil
}
