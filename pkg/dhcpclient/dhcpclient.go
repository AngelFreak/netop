// Package dhcpclient provides DHCP client functionality for obtaining network leases.
// This is distinct from pkg/dhcp which handles DHCP server operations for hotspot mode.
package dhcpclient

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// Timeout constants for DHCP operations
const (
	// UdhcpcDiscoverRetries is the number of DHCP DISCOVER packets udhcpc sends
	// before giving up. Default in BusyBox is 3; we raise to 6 so the total
	// discovery window matches NetworkManager's behavior more closely. This is
	// critical for USB ethernet adapters that take 1-3s to start passing frames
	// after `ip link up`, even though /sys/class/net/X/carrier already reads 1.
	UdhcpcDiscoverRetries = 6

	// UdhcpcDiscoverTimeout is the seconds between each DISCOVER retry.
	// 3s is BusyBox's default; total discover window = retries * timeout = 18s.
	UdhcpcDiscoverTimeout = 3

	// UdhcpcTryAgain is the seconds to wait before re-trying after a full
	// discover cycle. Only relevant when not using -n; included for documentation.
	UdhcpcTryAgain = 10

	// UdhcpcTimeout is the wall-clock timeout for the udhcpc process.
	// Must exceed UdhcpcDiscoverRetries * UdhcpcDiscoverTimeout (= 18s) plus
	// time for ARP probing, route setup, and script hooks.
	UdhcpcTimeout = 30 * time.Second

	// DhclientTimeout is the timeout for dhclient. Increased from 15s to 60s
	// to match dhclient's RFC-2131-compliant default timeout, which gives
	// flaky links (USB ethernet, slow switches) time to negotiate.
	DhclientTimeout = 60 * time.Second

	// CleanupTimeout is the timeout for cleanup operations (pkill, rm)
	CleanupTimeout = 500 * time.Millisecond

	// IPCheckTimeout is the timeout for checking acquired IP address
	IPCheckTimeout = 2 * time.Second

	// RetryDelay is how long to wait between DHCP attempts. Mirrors
	// NetworkManager's autoconnect-retry behavior.
	RetryDelay = 2 * time.Second
)

// Manager implements the DHCPClientManager interface
type Manager struct {
	executor    types.SystemExecutor
	logger      types.Logger
	dhcpTimeout time.Duration // Configurable overall DHCP timeout (0 = use defaults)
	runtimeDir  string        // overridable for tests; defaults to types.RuntimeDir
}

// NewManager creates a new DHCP client manager
func NewManager(executor types.SystemExecutor, logger types.Logger) *Manager {
	return &Manager{
		executor:   executor,
		logger:     logger,
		runtimeDir: types.RuntimeDir,
	}
}

// runDir returns the runtime directory for dhclient/udhcpc files (overridable
// in tests).
func (m *Manager) runDir() string {
	if m.runtimeDir != "" {
		return m.runtimeDir
	}
	return types.RuntimeDir
}

// SetDHCPTimeout configures the DHCP acquisition timeout from user config.
// If set, overrides the default UdhcpcTimeout and DhclientTimeout constants.
func (m *Manager) SetDHCPTimeout(timeout time.Duration) {
	if timeout > 0 {
		m.dhcpTimeout = timeout
	}
}

// getUdhcpcTimeout returns the configured timeout or the default
func (m *Manager) getUdhcpcTimeout() time.Duration {
	if m.dhcpTimeout > 0 {
		return m.dhcpTimeout
	}
	return UdhcpcTimeout
}

// getDhclientTimeout returns the configured timeout or the default
func (m *Manager) getDhclientTimeout() time.Duration {
	if m.dhcpTimeout > 0 {
		return m.dhcpTimeout
	}
	return DhclientTimeout
}

// Acquire obtains a DHCP lease for the interface.
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname.
//
// Client selection: wired interfaces prefer dhclient (RFC-2131 backoff, longer
// default timeout) because USB ethernet adapters often need a longer discovery
// window than udhcpc's default. WiFi interfaces prefer udhcpc (faster on the
// already-associated link). If the preferred client isn't installed, falls
// back to whichever is available.
//
// Each attempt is retried once on failure with a short delay, mirroring
// NetworkManager's autoconnect-retries default.
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

	hasUdhcpc := m.executor.HasCommand("udhcpc")
	hasDhclient := m.executor.HasCommand("dhclient")

	// Wired interfaces prefer dhclient — its default 60s timeout and RFC-2131
	// exponential backoff handle slow USB ethernet adapters and flaky switches
	// far better than udhcpc's 3-retry default. WiFi interfaces prefer udhcpc
	// (faster on already-associated links). dhclient remains the historical
	// fallback when udhcpc is unavailable.
	var attempt func() error
	switch {
	case isWiredInterface(iface) && hasDhclient:
		m.logger.Debug("Using dhclient for DHCP on wired interface", "interface", iface)
		attempt = func() error { return m.acquireDhclient(iface, hostname) }
	case hasUdhcpc:
		m.logger.Debug("Using udhcpc for DHCP", "interface", iface)
		attempt = func() error { return m.acquireUdhcpc(iface, hostname) }
	case hasDhclient:
		m.logger.Debug("Using dhclient for DHCP", "interface", iface)
		attempt = func() error { return m.acquireDhclient(iface, hostname) }
	default:
		return fmt.Errorf("no DHCP client found: install udhcpc (recommended) or dhclient")
	}

	if err := attempt(); err == nil {
		return nil
	} else {
		m.logger.Warn("DHCP attempt failed, retrying once", "interface", iface, "error", err)
		time.Sleep(RetryDelay)
		if retryErr := attempt(); retryErr != nil {
			return retryErr
		}
		return nil
	}
}

// isWiredInterface returns true if the interface name matches a wired prefix.
// Mirrors the detection logic in pkg/network/network.go: eth, enp, enx (USB
// MAC-based), eno (onboard), ens (slot-based), em (Dell/BSD-style), usb.
func isWiredInterface(iface string) bool {
	for _, prefix := range []string{"eth", "enp", "enx", "eno", "ens", "em", "usb"} {
		if strings.HasPrefix(iface, prefix) {
			return true
		}
	}
	return false
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

	// Prefer graceful shutdown via pidfile: SIGTERM lets udhcpc send a
	// DHCPRELEASE (via -R) and clean up the lease on the server side. Fall
	// back to pkill -9 if pidfile is missing or the process is already dead.
	pidFile := m.udhcpcPidFile(iface)
	if data, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(data))
		if pid != "" {
			if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "kill", pid); err != nil {
				m.logger.Debug("Failed to SIGTERM udhcpc via pidfile", "pid", pid, "error", err)
			}
		}
		_ = os.Remove(pidFile)
	}

	// Backstop: kill any udhcpc/dhclient still matching the interface. This
	// catches daemons started outside of netop or leftover processes from a
	// crashed run.
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "udhcpc.*"+escapedIface); err != nil {
		m.logger.Debug("No udhcpc process to kill", "interface", iface)
	}
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "dhclient.*"+escapedIface); err != nil {
		m.logger.Debug("No dhclient process to kill", "interface", iface)
	}

	// Clean up lease files
	leaseFiles := []string{
		"/var/lib/dhcp/dhclient." + iface + ".leases",
		m.runDir() + "/dhclient." + iface + ".leases",
	}
	for _, f := range leaseFiles {
		if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "rm", "-f", f); err != nil {
			errs = append(errs, fmt.Sprintf("failed to remove %s: %v", f, err))
		}
	}

	// Clean up interface-specific dhclient config
	confFile := m.runDir() + "/dhclient." + iface + ".conf"
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

// udhcpcPidFile returns the pidfile path for udhcpc on the given interface.
func (m *Manager) udhcpcPidFile(iface string) string {
	return m.runDir() + "/udhcpc." + iface + ".pid"
}

// acquireUdhcpc uses udhcpc (BusyBox) for DHCP acquisition.
// udhcpc daemonizes after obtaining the lease and stays alive to handle
// renewals. The PID is written to /run/net/udhcpc.<iface>.pid so Release
// can terminate it cleanly (which sends a DHCPRELEASE via -R).
// The default BusyBox build sends only 3 DISCOVERs at 3s intervals (~9s
// window), which is too short for many USB ethernet adapters, so -t/-T
// widen the discovery window to ~18s, closer to dhclient's default.
func (m *Manager) acquireUdhcpc(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// -i: interface
	// -n: exit if no lease acquired (so Acquire returns error on failure)
	// -p: pidfile so Release can find and kill the daemon
	// -R: send DHCPRELEASE when terminated (clean disconnect)
	// -B: set the broadcast flag in DISCOVER. Some embedded DHCP servers
	//     (e.g. IP radios, WISP gear) only reply via broadcast and silently
	//     drop clients that ask for unicast.
	// -t: number of DISCOVER retries (BusyBox default 3; we use 6)
	// -T: seconds between retries (BusyBox default 3)
	// -A: seconds to wait before re-trying after a full discover cycle
	// NOTE: no -q — udhcpc must stay running to renew the lease.
	args := []string{
		"-i", iface, "-n", "-p", m.udhcpcPidFile(iface), "-R", "-B",
		"-t", fmt.Sprintf("%d", UdhcpcDiscoverRetries),
		"-T", fmt.Sprintf("%d", UdhcpcDiscoverTimeout),
		"-A", fmt.Sprintf("%d", UdhcpcTryAgain),
	}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		args = append(args, "-x", "hostname:"+hostname)
	}

	_, err := m.executor.ExecuteWithTimeout(m.getUdhcpcTimeout(), "udhcpc", args...)
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
	// Use -1 (one attempt) to prevent dhclient from retrying indefinitely,
	// and -nw so it goes to background after obtaining a lease (keeping the
	// renewal daemon alive for lease renewal).
	dhclientTimeout := m.getDhclientTimeout()
	args := []string{fmt.Sprintf("%d", int(dhclientTimeout.Seconds())), "dhclient", "-v", "-1"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		// Create interface-specific dhclient.conf to avoid race conditions
		// with concurrent DHCP operations on different interfaces
		confContent := fmt.Sprintf("send host-name \"%s\";\n", hostname)
		dhclientConf := m.runDir() + "/dhclient." + iface + ".conf"
		if err := system.WriteSecureFile(dhclientConf, confContent); err != nil {
			// Hostname was explicitly requested but we can't create config - this is a hard error
			return fmt.Errorf("failed to create dhclient config for hostname: %w", err)
		}
		args = append(args, "-cf", dhclientConf)
	}
	args = append(args, iface)

	// Start dhclient with timeout wrapper. The -1 flag ensures dhclient
	// exits after the first attempt (success or fail) rather than retrying
	// forever. The timeout wrapper is a safety net in case dhclient hangs.
	//
	// The executor deadline must exceed the inner `timeout` value, otherwise
	// the default 30s command timeout SIGKILLs the `timeout` process before
	// dhclient's own window elapses — SIGKILL can't be forwarded, so dhclient
	// is orphaned and any lease past 30s is silently lost. Give a 5s margin.
	_, err := m.executor.ExecuteWithTimeout(dhclientTimeout+5*time.Second, "timeout", args...)
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
	return system.ParseIPFromOutput(output)
}
