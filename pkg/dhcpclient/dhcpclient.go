// Package dhcpclient provides DHCP client functionality for obtaining network leases.
// This is distinct from pkg/dhcp which handles DHCP server operations for hotspot mode.
package dhcpclient

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

// Timeout constants for DHCP operations
const (
	// UdhcpcTimeout is the timeout for udhcpc (faster client, typically 1-2s)
	UdhcpcTimeout = 10 * time.Second

	// DhclientTimeout is the timeout for dhclient (slower, typically 3-5s)
	DhclientTimeout = 15 * time.Second

	// CleanupTimeout is the timeout for cleanup operations (pkill, rm)
	CleanupTimeout = 500 * time.Millisecond

	// IPCheckTimeout is the timeout for checking acquired IP address
	IPCheckTimeout = 2 * time.Second
)

// Manager implements the DHCPClientManager interface
type Manager struct {
	executor types.SystemExecutor
	logger   types.Logger
}

// NewManager creates a new DHCP client manager
func NewManager(executor types.SystemExecutor, logger types.Logger) *Manager {
	return &Manager{
		executor: executor,
		logger:   logger,
	}
}

// Acquire obtains a DHCP lease for the interface.
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname.
func (m *Manager) Acquire(iface string, hostname string) error {
	// Validate interface name to prevent command injection
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	// Validate hostname if provided
	if hostname != "" {
		if err := types.ValidateHostname(hostname); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	m.logger.Info("Acquiring DHCP lease", "interface", iface)

	// Try udhcpc first (faster, ~1s vs 3-5s for dhclient)
	if m.executor.HasCommand("udhcpc") {
		m.logger.Debug("Using udhcpc for DHCP (faster)")
		return m.acquireUdhcpc(iface, hostname)
	}

	// Fall back to dhclient
	m.logger.Debug("Using dhclient for DHCP")
	return m.acquireDhclient(iface, hostname)
}

// Release stops any running DHCP client for the interface and cleans up lease files.
// This is a best-effort cleanup operation - errors are logged but not returned
// since partial cleanup is acceptable for network operations.
func (m *Manager) Release(iface string) error {
	// Validate interface name
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	m.logger.Debug("Releasing DHCP lease", "interface", iface)

	var errs []string

	// Escape regex special characters in interface name (e.g., eth-0 has '-' which is a regex char)
	escapedIface := regexp.QuoteMeta(iface)

	// Kill both DHCP clients to ensure cleanup
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "udhcpc.*"+escapedIface); err != nil {
		m.logger.Debug("No udhcpc process to kill", "interface", iface)
	}
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "dhclient.*"+escapedIface); err != nil {
		m.logger.Debug("No dhclient process to kill", "interface", iface)
	}

	// Clean up lease files
	leaseFiles := []string{
		"/var/lib/dhcp/dhclient." + iface + ".leases",
		types.RuntimeDir + "/dhclient." + iface + ".leases",
	}
	for _, f := range leaseFiles {
		if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "rm", "-f", f); err != nil {
			errs = append(errs, fmt.Sprintf("failed to remove %s: %v", f, err))
		}
	}

	// Clean up interface-specific dhclient config
	confFile := types.RuntimeDir + "/dhclient." + iface + ".conf"
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "rm", "-f", confFile); err != nil {
		m.logger.Debug("Failed to remove dhclient config", "file", confFile, "error", err)
	}

	if len(errs) > 0 {
		m.logger.Debug("Some cleanup operations failed", "errors", strings.Join(errs, "; "))
	}

	return nil
}

// Renew renews the DHCP lease for the interface.
// For simplicity, this performs a fresh acquisition (same behavior as original implementation).
func (m *Manager) Renew(iface string, hostname string) error {
	m.logger.Info("Renewing DHCP lease", "interface", iface)
	return m.Acquire(iface, hostname)
}

// acquireUdhcpc uses udhcpc (BusyBox) for faster DHCP acquisition
func (m *Manager) acquireUdhcpc(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// Build udhcpc command
	// -i: interface, -n: fail if no lease (don't go to background), -q: quit after obtaining lease
	args := []string{"-i", iface, "-n", "-q"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		args = append(args, "-x", "hostname:"+hostname)
	}

	_, err := m.executor.ExecuteWithTimeout(UdhcpcTimeout, "udhcpc", args...)
	if err != nil {
		// Clean up any partial state on failure
		m.Release(iface)
		return fmt.Errorf("udhcpc failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// acquireDhclient uses dhclient (ISC) as fallback
func (m *Manager) acquireDhclient(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// Build dhclient command with optional hostname via config file
	args := []string{fmt.Sprintf("%d", int(DhclientTimeout.Seconds())), "dhclient", "-v"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		// Create interface-specific dhclient.conf to avoid race conditions
		// with concurrent DHCP operations on different interfaces
		confContent := fmt.Sprintf("send host-name \"%s\";\n", hostname)
		dhclientConf := types.RuntimeDir + "/dhclient." + iface + ".conf"
		if _, err := m.executor.ExecuteWithInput("install", confContent, "-m", "0600", "/dev/stdin", dhclientConf); err != nil {
			// Hostname was explicitly requested but we can't create config - this is a hard error
			return fmt.Errorf("failed to create dhclient config for hostname: %w", err)
		}
		args = append(args, "-cf", dhclientConf)
	}
	args = append(args, iface)

	// Start dhclient with timeout wrapper
	_, err := m.executor.Execute("timeout", args...)
	if err != nil {
		// Clean up any partial state on failure
		m.Release(iface)
		return fmt.Errorf("dhclient failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// logAcquiredIP logs the IP address after successful DHCP
func (m *Manager) logAcquiredIP(iface string) {
	ipOutput, err := m.executor.ExecuteWithTimeout(IPCheckTimeout, "ip", "addr", "show", iface)
	if err == nil {
		ip := m.parseIPAddress(ipOutput)
		if ip != nil {
			m.logger.Info("Address acquired", "ip", ip.String())
		}
	}
}

// parseIPAddress extracts the first IPv4 address from ip addr output
func (m *Manager) parseIPAddress(output string) net.IP {
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
