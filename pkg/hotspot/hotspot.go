package hotspot

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
)

// hotspotManagerImpl implements the HotspotManager interface
type hotspotManagerImpl struct {
	executor        types.SystemExecutor
	logger          types.Logger
	hostapdPidFile  string
	dnsmasqPidFile  string
	hostapdConfFile string
	dnsmasqConfFile string
	stateFile       string // Persists hotspot interface and outInterface for crash recovery
	currentConfig   *types.HotspotConfig
	outInterface    string // Interface for NAT routing (e.g., eth0)
	prevIPForward   string // /proc/.../ip_forward value before we enabled it, for restore ("0"/"1"/"" if unknown)
}

// NewHotspotManager creates a new hotspot manager
func NewHotspotManager(executor types.SystemExecutor, logger types.Logger) types.HotspotManager {
	return &hotspotManagerImpl{
		executor:        executor,
		logger:          logger,
		hostapdPidFile:  types.RuntimeDir + "/hostapd.pid",
		dnsmasqPidFile:  types.RuntimeDir + "/dnsmasq-hotspot.pid",
		hostapdConfFile: types.RuntimeDir + "/hostapd.conf",
		dnsmasqConfFile: types.RuntimeDir + "/dnsmasq-hotspot.conf",
		stateFile:       types.RuntimeDir + "/hotspot-state",
	}
}

// Start starts the WiFi hotspot with the given configuration
func (h *hotspotManagerImpl) Start(config *types.HotspotConfig) error {
	h.logger.Info("Starting hotspot", "ssid", config.SSID, "interface", config.Interface)

	// Validate configuration
	if err := h.validateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Check if already running
	if h.isRunning() {
		return fmt.Errorf("hotspot is already running")
	}

	// Setup interface (with cleanup on failure)
	if err := h.setupInterface(config); err != nil {
		return err
	}

	// Generate hostapd configuration
	if err := h.generateHostapdConfig(config); err != nil {
		h.cleanupInterface(config.Interface)
		return fmt.Errorf("failed to generate hostapd config: %w", err)
	}

	// Start hostapd
	h.logger.Debug("Starting hostapd")
	if _, err := h.executor.ExecuteWithTimeout(10*time.Second, "hostapd", "-B", "-P", h.hostapdPidFile, h.hostapdConfFile); err != nil {
		h.cleanupInterface(config.Interface)
		return fmt.Errorf("failed to start hostapd: %w", err)
	}

	// Verify hostapd actually started (poll for up to 5 seconds)
	if err := h.waitForHostapd(); err != nil {
		os.Remove(h.hostapdPidFile)
		h.cleanupInterface(config.Interface)
		return err
	}

	// Generate dnsmasq configuration
	if err := h.generateDnsmasqConfig(config); err != nil {
		h.stopHostapd()
		h.cleanupInterface(config.Interface)
		return fmt.Errorf("failed to generate dnsmasq config: %w", err)
	}

	// Start dnsmasq for DHCP
	h.logger.Debug("Starting dnsmasq")
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "dnsmasq", "-C", h.dnsmasqConfFile, "-x", h.dnsmasqPidFile); err != nil {
		h.stopHostapd()
		h.cleanupInterface(config.Interface)
		return fmt.Errorf("failed to start dnsmasq: %w", err)
	}

	// Setup NAT/IP forwarding for internet sharing
	if err := h.setupNAT(config.Interface); err != nil {
		h.logger.Warn("Failed to setup NAT", "error", err.Error())
		// Continue anyway - hotspot will work but without internet sharing
	}

	h.currentConfig = config

	// Persist state for crash recovery (so Stop can clean up NAT even after restart)
	h.saveState(config.Interface)

	h.logger.Info("Hotspot started successfully", "ssid", config.SSID)
	return nil
}

// setupInterface brings up the interface and configures IP (with cleanup on failure)
func (h *hotspotManagerImpl) setupInterface(config *types.HotspotConfig) error {
	// Bring interface down
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", config.Interface, "down"); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Set interface to AP mode
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "iw", config.Interface, "set", "type", "__ap"); err != nil {
		h.logger.Warn("Failed to set interface to AP mode, continuing anyway", "error", err.Error())
	}

	// Bring interface up
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", config.Interface, "up"); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Set IP address on interface - cleanup on failure
	netmask := config.Netmask
	if netmask == "" {
		netmask = "24"
	}
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "addr", "add", config.Gateway+"/"+netmask, "dev", config.Interface); err != nil {
		h.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "set", config.Interface, "down")
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	return nil
}

// cleanupInterface cleans up interface after a failure
func (h *hotspotManagerImpl) cleanupInterface(iface string) {
	h.executor.ExecuteWithTimeout(2*time.Second, "ip", "addr", "flush", "dev", iface)
	h.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "set", iface, "down")
}

// waitForHostapd waits for hostapd to start (up to 5 seconds)
func (h *hotspotManagerImpl) waitForHostapd() error {
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if h.hostapdRunning() {
			return nil
		}
	}
	return fmt.Errorf("hostapd failed to start")
}

// setupNAT configures IP forwarding and NAT masquerade
func (h *hotspotManagerImpl) setupNAT(hotspotIface string) error {
	// Record the current forwarding state so teardown can restore it instead
	// of unconditionally disabling forwarding the host may have had enabled.
	if out, err := h.executor.ExecuteWithTimeout(2*time.Second, "cat", "/proc/sys/net/ipv4/ip_forward"); err == nil {
		h.prevIPForward = strings.TrimSpace(out)
	}

	// Enable IP forwarding
	if _, err := h.executor.ExecuteWithTimeout(2*time.Second, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Find outbound interface if not specified
	outIface := h.outInterface
	if outIface == "" {
		outIface = h.detectOutInterface(hotspotIface)
	}

	if outIface == "" {
		h.logger.Warn("No outbound interface detected, skipping NAT setup")
		return nil
	}

	h.logger.Debug("Setting up NAT", "outInterface", outIface, "hotspotInterface", hotspotIface)

	// Remove existing rules first to prevent duplicates from repeated Start/Stop cycles
	h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE")
	h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-D", "FORWARD", "-i", hotspotIface, "-j", "ACCEPT")
	h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-D", "FORWARD", "-o", hotspotIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Setup NAT masquerade
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE"); err != nil {
		return fmt.Errorf("failed to setup masquerade: %w", err)
	}

	// Allow forwarding from hotspot interface
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "iptables", "-A", "FORWARD", "-i", hotspotIface, "-j", "ACCEPT"); err != nil {
		h.logger.Warn("Failed to setup forward rule", "error", err.Error())
	}

	// Allow established connections back
	if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "iptables", "-A", "FORWARD", "-o", hotspotIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		h.logger.Warn("Failed to setup established forward rule", "error", err.Error())
	}

	h.outInterface = outIface
	return nil
}

// detectOutInterface finds the default route interface (excluding hotspot interface)
func (h *hotspotManagerImpl) detectOutInterface(exclude string) string {
	output, err := h.executor.ExecuteWithTimeout(2*time.Second, "ip", "route", "show", "default")
	if err != nil {
		return ""
	}

	// Parse "default via X.X.X.X dev ethX" format
	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			iface := fields[i+1]
			if iface != exclude {
				return iface
			}
		}
	}
	return ""
}

// cleanupNAT removes NAT rules and disables IP forwarding
func (h *hotspotManagerImpl) cleanupNAT(hotspotIface string) {
	outIface := h.outInterface
	if outIface != "" {
		// Remove NAT rules (ignore errors - rules may not exist)
		h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE")
		h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-D", "FORWARD", "-i", hotspotIface, "-j", "ACCEPT")
		h.executor.ExecuteWithTimeout(2*time.Second, "iptables", "-D", "FORWARD", "-o", hotspotIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}

	// Restore IP forwarding to its pre-hotspot value rather than forcing it
	// off — the host may have had forwarding enabled before netop ran. Default
	// to "0" only when we never recorded the prior value.
	restore := h.prevIPForward
	if restore != "0" && restore != "1" {
		restore = "0"
	}
	if _, err := h.executor.ExecuteWithTimeout(2*time.Second, "sh", "-c", "echo "+restore+" > /proc/sys/net/ipv4/ip_forward"); err != nil {
		h.logger.Warn("Failed to restore IP forwarding", "error", err.Error())
	}
}

// Stop stops the running hotspot
func (h *hotspotManagerImpl) Stop() error {
	h.logger.Info("Stopping hotspot")

	// Recover state from file if currentConfig is nil (e.g., after crash/restart)
	if h.currentConfig == nil || h.outInterface == "" {
		h.loadState()
	}

	// If neither daemon is running and we have no recorded state, there is
	// genuinely nothing to clean up. But if the daemons died on their own
	// while state remains, fall through and tear down the NAT rules and
	// interface so MASQUERADE and ip_forward aren't left dangling.
	if !h.isRunning() && h.currentConfig == nil {
		os.Remove(h.stateFile)
		return fmt.Errorf("hotspot is not running")
	}

	var errors []string

	// Clean up NAT rules first
	if h.currentConfig != nil {
		h.cleanupNAT(h.currentConfig.Interface)
	} else {
		// Even without config, disable IP forwarding as a safety measure
		h.cleanupNAT("")
	}

	// Stop dnsmasq
	if err := h.stopDnsmasq(); err != nil {
		errors = append(errors, fmt.Sprintf("dnsmasq: %v", err))
	}

	// Stop hostapd
	if err := h.stopHostapd(); err != nil {
		errors = append(errors, fmt.Sprintf("hostapd: %v", err))
	}

	// Clean up interface if we have config
	if h.currentConfig != nil {
		// Remove IP address
		if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "addr", "flush", "dev", h.currentConfig.Interface); err != nil {
			h.logger.Warn("Failed to flush IP addresses", "error", err.Error())
		}

		// Bring interface down
		if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", h.currentConfig.Interface, "down"); err != nil {
			h.logger.Warn("Failed to bring interface down", "error", err.Error())
		}

		// Set back to managed mode
		if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "iw", h.currentConfig.Interface, "set", "type", "managed"); err != nil {
			h.logger.Warn("Failed to set interface to managed mode", "error", err.Error())
		}

		// Bring interface back up
		if _, err := h.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", h.currentConfig.Interface, "up"); err != nil {
			h.logger.Warn("Failed to bring interface up", "error", err.Error())
		}
	}

	// Clean up configuration files
	os.Remove(h.hostapdConfFile)
	os.Remove(h.dnsmasqConfFile)

	h.currentConfig = nil
	h.outInterface = ""
	os.Remove(h.stateFile)

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping hotspot: %s", strings.Join(errors, "; "))
	}

	h.logger.Info("Hotspot stopped successfully")
	return nil
}

// GetStatus returns the current hotspot status
func (h *hotspotManagerImpl) GetStatus() (*types.HotspotStatus, error) {
	status := &types.HotspotStatus{
		Running: h.isRunning(),
	}

	if h.currentConfig != nil {
		status.Interface = h.currentConfig.Interface
		status.SSID = h.currentConfig.SSID
		if ip := net.ParseIP(h.currentConfig.Gateway); ip != nil {
			status.Gateway = ip
		}

		// Try to get connected clients count
		if h.isRunning() {
			clients, err := h.getConnectedClients()
			if err == nil {
				status.Clients = clients
			}
		}
	}

	return status, nil
}

// validateConfig validates the hotspot configuration
func (h *hotspotManagerImpl) validateConfig(config *types.HotspotConfig) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	if strings.ContainsAny(config.Interface, " \t\n\r/") {
		return fmt.Errorf("invalid interface name: %q", config.Interface)
	}
	if config.SSID == "" {
		return fmt.Errorf("SSID is required")
	}
	if config.Password != "" && (len(config.Password) < 8 || len(config.Password) > 63) {
		// hostapd requires WPA2 passphrases to be 8..63 characters; anything
		// outside that range makes it fail to start with a cryptic error.
		return fmt.Errorf("password must be 8-63 characters")
	}
	if !isValidChannel(config.Channel) {
		return fmt.Errorf("invalid channel %d (valid: 1-14 for 2.4GHz, 36-165 for 5GHz)", config.Channel)
	}
	if config.Gateway == "" {
		return fmt.Errorf("gateway is required")
	}
	if net.ParseIP(config.Gateway) == nil {
		return fmt.Errorf("invalid gateway IP address: %q", config.Gateway)
	}
	if config.IPRange == "" {
		return fmt.Errorf("IP range is required")
	}
	if err := validateIPRange(config.IPRange); err != nil {
		return fmt.Errorf("invalid IP range: %w", err)
	}
	for _, dns := range config.DNS {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("invalid DNS server: %q", dns)
		}
	}

	return nil
}

// validateIPRange validates that an IP range is in the format "startIP,endIP"
func validateIPRange(ipRange string) error {
	parts := strings.Split(ipRange, ",")
	if len(parts) != 2 {
		return fmt.Errorf("expected format 'startIP,endIP', got %q", ipRange)
	}
	if net.ParseIP(strings.TrimSpace(parts[0])) == nil {
		return fmt.Errorf("invalid start IP: %q", parts[0])
	}
	if net.ParseIP(strings.TrimSpace(parts[1])) == nil {
		return fmt.Errorf("invalid end IP: %q", parts[1])
	}
	return nil
}

// isValidChannel checks if the channel is valid for 2.4GHz or 5GHz bands
func isValidChannel(channel int) bool {
	// 2.4GHz channels: 1-14 (14 is Japan only but allowed)
	if channel >= 1 && channel <= 14 {
		return true
	}
	// 5GHz channels (common UNII bands)
	valid5GHz := []int{
		// UNII-1 (5150-5250 MHz)
		36, 40, 44, 48,
		// UNII-2A (5250-5350 MHz)
		52, 56, 60, 64,
		// UNII-2C (5470-5725 MHz)
		100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
		// UNII-3 (5725-5850 MHz)
		149, 153, 157, 161, 165,
	}
	for _, ch := range valid5GHz {
		if channel == ch {
			return true
		}
	}
	return false
}

// escapeHostapdString escapes special characters for hostapd config values
// This prevents injection attacks via specially crafted SSIDs/passwords
func escapeHostapdString(s string) string {
	// Escape backslashes first (must be done before escaping other characters)
	s = strings.ReplaceAll(s, `\`, `\\`)
	// Escape newlines to prevent config injection
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// generateHostapdConfig generates hostapd configuration file
func (h *hotspotManagerImpl) generateHostapdConfig(config *types.HotspotConfig) error {
	var sb strings.Builder

	// Escape SSID and password to prevent injection
	escapedSSID := escapeHostapdString(config.SSID)

	sb.WriteString(fmt.Sprintf("interface=%s\n", config.Interface))
	sb.WriteString("driver=nl80211\n")
	sb.WriteString(fmt.Sprintf("ssid=%s\n", escapedSSID))

	// Set hw_mode based on channel (g for 2.4GHz, a for 5GHz)
	if config.Channel >= 36 {
		sb.WriteString("hw_mode=a\n")
	} else {
		sb.WriteString("hw_mode=g\n")
	}

	sb.WriteString(fmt.Sprintf("channel=%d\n", config.Channel))
	sb.WriteString("macaddr_acl=0\n")
	sb.WriteString("ignore_broadcast_ssid=0\n")

	if config.Password != "" {
		escapedPassword := escapeHostapdString(config.Password)
		sb.WriteString("auth_algs=1\n")
		sb.WriteString("wpa=2\n")
		sb.WriteString(fmt.Sprintf("wpa_passphrase=%s\n", escapedPassword))
		sb.WriteString("wpa_key_mgmt=WPA-PSK\n")
		sb.WriteString("rsn_pairwise=CCMP\n")
	}

	// Write with secure permissions (0600) - config may contain password
	if err := os.WriteFile(h.hostapdConfFile, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write hostapd config: %w", err)
	}

	return nil
}

// generateDnsmasqConfig generates dnsmasq configuration file
func (h *hotspotManagerImpl) generateDnsmasqConfig(config *types.HotspotConfig) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("interface=%s\n", config.Interface))
	sb.WriteString("bind-interfaces\n")
	sb.WriteString(fmt.Sprintf("dhcp-range=%s,12h\n", config.IPRange))

	// Determine DNS servers to use
	dnsServers := config.DNS
	if len(dnsServers) == 0 {
		// Default DNS servers
		dnsServers = []string{"8.8.8.8", "8.8.4.4"}
	}

	// Add DNS servers for forwarding
	for _, dns := range dnsServers {
		sb.WriteString(fmt.Sprintf("server=%s\n", dns))
	}

	// Gateway option (option 3)
	sb.WriteString(fmt.Sprintf("dhcp-option=3,%s\n", config.Gateway))

	// DNS option (option 6) - only if we have DNS servers
	sb.WriteString(fmt.Sprintf("dhcp-option=6,%s\n", strings.Join(dnsServers, ",")))

	// Write with secure permissions (0600)
	if err := os.WriteFile(h.dnsmasqConfFile, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write dnsmasq config: %w", err)
	}

	return nil
}

// isRunning checks if the hotspot is currently running.
// Returns true if either daemon is running (not just both), so Stop can
// clean up partial failures where one daemon died but the other is alive.
func (h *hotspotManagerImpl) isRunning() bool {
	return h.hostapdRunning() || h.dnsmasqRunning()
}

// hostapdRunning checks if hostapd is running by verifying PID and process name
func (h *hotspotManagerImpl) hostapdRunning() bool {
	return h.processRunning(h.hostapdPidFile, "hostapd")
}

// dnsmasqRunning checks if dnsmasq is running by verifying PID and process name
func (h *hotspotManagerImpl) dnsmasqRunning() bool {
	return h.processRunning(h.dnsmasqPidFile, "dnsmasq")
}

// processRunning checks if a process from a PID file is running and matches the expected name
func (h *hotspotManagerImpl) processRunning(pidFile, expectedName string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false
	}

	// Verify the process exists AND is the expected program (not a reused PID)
	commPath := filepath.Join("/proc", pid, "comm")
	comm, err := os.ReadFile(commPath)
	if err != nil {
		return false
	}

	processName := strings.TrimSpace(string(comm))
	if processName == expectedName {
		return true
	}

	// Fall back to checking if process exists at all (for environments
	// where comm doesn't match, e.g. wrapper scripts)
	h.logger.Debug("PID process name mismatch", "pid", pid, "expected", expectedName, "actual", processName)
	return false
}

// stopHostapd stops the hostapd process
func (h *hotspotManagerImpl) stopHostapd() error {
	data, err := os.ReadFile(h.hostapdPidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already exited — nothing to kill, don't block teardown
		}
		return fmt.Errorf("failed to read hostapd PID: %w", err)
	}

	pid := strings.TrimSpace(string(data))
	if !isValidPID(pid) {
		os.Remove(h.hostapdPidFile)
		return fmt.Errorf("invalid PID in %s: %q", h.hostapdPidFile, pid)
	}
	if err := h.killProcess(pid); err != nil {
		return fmt.Errorf("failed to kill hostapd: %w", err)
	}

	os.Remove(h.hostapdPidFile)
	return nil
}

// stopDnsmasq stops the dnsmasq process
func (h *hotspotManagerImpl) stopDnsmasq() error {
	data, err := os.ReadFile(h.dnsmasqPidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already exited — nothing to kill, don't block teardown
		}
		return fmt.Errorf("failed to read dnsmasq PID: %w", err)
	}

	pid := strings.TrimSpace(string(data))
	if !isValidPID(pid) {
		os.Remove(h.dnsmasqPidFile)
		return fmt.Errorf("invalid PID in %s: %q", h.dnsmasqPidFile, pid)
	}
	if err := h.killProcess(pid); err != nil {
		return fmt.Errorf("failed to kill dnsmasq: %w", err)
	}

	os.Remove(h.dnsmasqPidFile)
	return nil
}

// isValidPID checks that a PID string is a positive integer
func isValidPID(pid string) bool {
	if pid == "" {
		return false
	}
	n, err := strconv.Atoi(pid)
	return err == nil && n > 0
}

// saveState persists hotspot interface and outInterface to a state file for crash recovery
func (h *hotspotManagerImpl) saveState(hotspotIface string) {
	// Format: hotspotInterface|outInterface|prevIPForward
	content := hotspotIface + "|" + h.outInterface + "|" + h.prevIPForward
	if err := os.WriteFile(h.stateFile, []byte(content), 0600); err != nil {
		h.logger.Debug("Failed to save hotspot state", "error", err)
	}
}

// loadState recovers hotspot state from the state file (e.g., after crash/restart)
func (h *hotspotManagerImpl) loadState() {
	data, err := os.ReadFile(h.stateFile)
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), "|", 3)
	if len(parts) >= 1 && parts[0] != "" {
		h.currentConfig = &types.HotspotConfig{Interface: parts[0]}
	}
	if len(parts) >= 2 && parts[1] != "" {
		h.outInterface = parts[1]
	}
	if len(parts) >= 3 && parts[2] != "" {
		h.prevIPForward = parts[2]
	}
}

// killProcess kills a process with SIGTERM, falling back to SIGKILL if needed
func (h *hotspotManagerImpl) killProcess(pid string) error {
	// Try SIGTERM first
	_, err := h.executor.ExecuteWithTimeout(2*time.Second, "kill", pid)
	if err != nil {
		return err
	}

	// Wait briefly for process to terminate
	time.Sleep(500 * time.Millisecond)

	// Check if still running, force kill if needed
	processPath := filepath.Join("/proc", pid)
	if _, err := os.Stat(processPath); err == nil {
		// Process still running, use SIGKILL
		h.executor.ExecuteWithTimeout(2*time.Second, "kill", "-9", pid)
	}

	return nil
}

// getConnectedClients returns the number of connected clients
func (h *hotspotManagerImpl) getConnectedClients() (int, error) {
	if h.currentConfig == nil {
		return 0, nil
	}

	// Get station list from hostapd
	output, err := h.executor.ExecuteWithTimeout(5*time.Second, "iw", "dev", h.currentConfig.Interface, "station", "dump")
	if err != nil {
		return 0, err
	}

	// Count "Station" lines
	count := 0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Station ") {
			count++
		}
	}

	return count, nil
}

// GetDnsmasqLeases reads and returns current DHCP leases
func GetDnsmasqLeases(leasesPath string) ([]string, error) {
	data, err := os.ReadFile(leasesPath)
	if err != nil {
		return nil, err
	}

	var leases []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			leases = append(leases, line)
		}
	}

	return leases, nil
}

// ParseDnsmasqLease parses a dnsmasq lease line
func ParseDnsmasqLease(lease string) (timestamp int64, mac, ip, hostname string, err error) {
	parts := strings.Fields(lease)
	if len(parts) < 4 {
		return 0, "", "", "", fmt.Errorf("invalid lease format")
	}

	timestamp, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", "", "", fmt.Errorf("invalid timestamp: %w", err)
	}

	mac = parts[1]
	ip = parts[2]
	hostname = parts[3]

	return timestamp, mac, ip, hostname, nil
}
