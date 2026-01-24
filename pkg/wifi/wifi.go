package wifi

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// Compiled regexes for parsing - initialized once at package load
var (
	// WiFi scan result parsing
	ssidRegex   = regexp.MustCompile(`SSID: (.+)`)
	bssidRegex  = regexp.MustCompile(`BSS ([0-9a-f:]+)`)
	signalRegex = regexp.MustCompile(`signal: ([-\d.]+)`)
	freqRegex   = regexp.MustCompile(`freq: (.+)`)

	// SSID hex escape decoding
	hexEscapeRegex = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

	// wpa_cli status parsing
	wpaSSIDRegex  = regexp.MustCompile(`(?m)^ssid=(.+)$`)
	wpaStateRegex = regexp.MustCompile(`(?m)^wpa_state=(.+)$`)
	wpaBSSIDRegex = regexp.MustCompile(`(?m)^bssid=(.+)$`)

	// IP address parsing
	inetRegex = regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)

	// BSSID validation - exactly 6 pairs of hex digits separated by colons
	validBSSIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
)

// Manager implements the WiFiManager interface
type Manager struct {
	executor           types.SystemExecutor
	logger             types.Logger
	iface              string
	associationTimeout time.Duration // Configurable for testing, defaults to 30s
	dhcpClient         types.DHCPClientManager
}

// NewManager creates a new WiFi manager
func NewManager(executor types.SystemExecutor, logger types.Logger, iface string, dhcpClient types.DHCPClientManager) *Manager {
	return &Manager{
		executor:           executor,
		logger:             logger,
		iface:              iface,
		associationTimeout: 30 * time.Second, // Default timeout
		dhcpClient:         dhcpClient,
	}
}

// Scan scans for available WiFi networks
func (m *Manager) Scan() ([]types.WiFiNetwork, error) {
	m.logger.Info("Scanning for WiFi networks", "interface", m.iface)

	// Bring interface up if needed
	_, err := m.executor.Execute("ip", "link", "set", m.iface, "up")
	if err != nil {
		m.logger.Warn("Failed to bring interface up", "error", err)
	}

	// Note: Don't kill wpa_supplicant here - iw scan works even with active connection
	// This prevents dropping existing connections during scan

	// Try to get cached scan results first (fast path)
	output, err := m.executor.ExecuteWithTimeout(5*time.Second, "iw", m.iface, "scan", "dump")
	if err != nil || output == "" || !strings.Contains(output, "BSS") {
		// No cached results, trigger a new scan
		_, err = m.executor.ExecuteWithTimeout(10*time.Second, "iw", m.iface, "scan")
		if err != nil {
			return nil, fmt.Errorf("failed to scan: %w", err)
		}
		// Get fresh scan results
		output, err = m.executor.ExecuteWithTimeout(5*time.Second, "iw", m.iface, "scan", "dump")
		if err != nil {
			return nil, fmt.Errorf("failed to get scan results: %w", err)
		}
	}

	return m.parseScanResults(output)
}

// Connect connects to a WiFi network without BSSID pinning
func (m *Manager) Connect(ssid, password, hostname string) error {
	return m.ConnectWithBSSID(ssid, password, "", hostname)
}

// ConnectWithBSSID connects to a WiFi network with optional BSSID pinning
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname
func (m *Manager) ConnectWithBSSID(ssid, password, bssid, hostname string) error {
	// Validate inputs
	if err := types.ValidateSSID(ssid); err != nil {
		return fmt.Errorf("invalid SSID: %w", err)
	}
	if err := types.ValidatePSK(password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	if hostname != "" {
		if err := types.ValidateHostname(hostname); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	var err error
	if bssid != "" {
		m.logger.Info("Connecting to WiFi network with BSSID pinning", "ssid", ssid, "bssid", bssid, "interface", m.iface)
	} else {
		m.logger.Info("Connecting to WiFi network", "ssid", ssid, "interface", m.iface)
	}

	// Only disconnect if connected to a different network
	// This avoids unnecessary interface cycling when reconnecting to same network
	currentSSID, _ := m.getCurrentSSID()
	if currentSSID != "" && currentSSID != ssid {
		m.logger.Debug("Disconnecting from current network", "currentSSID", currentSSID)
		_ = m.Disconnect()
	}

	// Skip scan verification - wpa_supplicant will fail quickly if network is not in range
	// This saves 2-3 seconds on every connection

	// Create wpa_supplicant config with optional BSSID pinning
	config := m.generateWPAConfig(ssid, password, bssid)
	// Don't log config - it contains credentials
	m.logger.Debug("Generated WPA config", "ssid", ssid, "hasBSSID", bssid != "")

	// Write config to temp file in secure runtime directory
	tempConfig := types.RuntimeDir + "/wpa_supplicant.conf"
	// Remove any existing file to avoid permission issues
	_, err = m.executor.Execute("rm", "-f", tempConfig)
	if err != nil {
		m.logger.Warn("Failed to remove old config file", "error", err)
	}
	err = m.writeFile(tempConfig, config)
	if err != nil {
		return fmt.Errorf("failed to write WPA config: %w", err)
	}

	// Terminate existing wpa_supplicant for this interface only
	m.terminateWpaSupplicant()

	// Bring interface up before starting wpa_supplicant
	_, err = m.executor.Execute("ip", "link", "set", m.iface, "up")
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Ensure wpa_supplicant control directory exists
	_, _ = m.executor.Execute("mkdir", "-p", "/run/wpa_supplicant")

	// Start wpa_supplicant with control interface for wpa_cli communication
	_, err = m.executor.Execute("wpa_supplicant", "-B", "-i", m.iface, "-c", tempConfig, "-C", "/run/wpa_supplicant")
	if err != nil {
		return fmt.Errorf("failed to start wpa_supplicant: %w", err)
	}

	// Wait for wpa_supplicant to be ready (polls up to 1 second, usually ready in <100ms)
	if !m.waitForWpaSupplicantReady(1 * time.Second) {
		m.logger.Warn("wpa_supplicant may not be fully ready, proceeding anyway")
	}

	// Wait for association with the access point
	err = m.waitForAssociation(ssid)
	if err != nil {
		// Clean up wpa_supplicant on failure (interface-specific)
		m.terminateWpaSupplicant()
		return fmt.Errorf("failed to associate with access point: %w", err)
	}

	// Get DHCP lease with optional hostname
	err = m.obtainDHCP(hostname)
	if err != nil {
		// Clean up wpa_supplicant on failure (interface-specific)
		m.terminateWpaSupplicant()
		return fmt.Errorf("failed to obtain DHCP lease: %w", err)
	}

	// Skip captive portal check - it adds unnecessary delay
	// Users can manually check if they suspect a captive portal

	m.logger.Debug("Successfully connected to WiFi network", "ssid", ssid)
	return nil
}

// Disconnect disconnects from the current WiFi network
func (m *Manager) Disconnect() error {
	m.logger.Info("Disconnecting from WiFi network", "interface", m.iface)

	// Terminate wpa_supplicant for this interface only (not global)
	m.terminateWpaSupplicant()

	// Terminate dhclient for this interface only (not global)
	m.terminateDhclient()

	// Flush all IP addresses from interface
	if _, err := m.executor.Execute("ip", "addr", "flush", "dev", m.iface); err != nil {
		m.logger.Debug("Failed to flush IP addresses", "error", err)
	}

	// Flush all routes for this interface
	if _, err := m.executor.Execute("ip", "route", "flush", "dev", m.iface); err != nil {
		m.logger.Debug("Failed to flush routes", "error", err)
	}

	// Bring interface down
	if _, err := m.executor.Execute("ip", "link", "set", m.iface, "down"); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	return nil
}

// ListConnections lists current network connections
func (m *Manager) ListConnections() ([]types.Connection, error) {
	m.logger.Debug("Listing network connections")

	var connections []types.Connection

	// Get IP addresses
	ipOutput, err := m.executor.Execute("ip", "addr", "show", m.iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses: %w", err)
	}

	ip := m.parseIPAddress(ipOutput)

	// Get routes for gateway
	routeOutput, err := m.executor.Execute("ip", "route", "show", "dev", m.iface)
	if err != nil {
		m.logger.Debug("Failed to get routes", "error", err)
	}

	gateway := m.parseGateway(routeOutput)

	// Get current SSID
	ssid, err := m.getCurrentSSID()
	if err != nil {
		m.logger.Debug("Failed to get current SSID", "error", err)
	}

	// Get DNS servers
	dns, err := m.getDNSServers()
	if err != nil {
		m.logger.Debug("Failed to get DNS servers", "error", err)
	}

	connection := types.Connection{
		Interface: m.iface,
		SSID:      ssid,
		State:     "connected", // Assume connected if we have an IP
		IP:        ip,
		Gateway:   gateway,
		DNS:       dns,
	}

	connections = append(connections, connection)
	return connections, nil
}

// GetInterface returns the managed interface name
func (m *Manager) GetInterface() string {
	return m.iface
}

// Helper functions

func (m *Manager) parseScanResults(output string) ([]types.WiFiNetwork, error) {
	if m.logger != nil {
		m.logger.Debug("Parsing scan results", "output", output)
	}
	networksMap := make(map[string]*types.WiFiNetwork)
	lines := strings.Split(output, "\n")

	var currentNetwork *types.WiFiNetwork
	var currentSecurity string
	// Use package-level compiled regexes for better performance

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "BSS ") {
			// New network
			if currentNetwork != nil && currentNetwork.SSID != "" {
				currentNetwork.Security = currentSecurity
				if existing, ok := networksMap[currentNetwork.SSID]; !ok || currentNetwork.Signal > existing.Signal {
					networksMap[currentNetwork.SSID] = currentNetwork
				}
				if m.logger != nil {
					m.logger.Debug("Parsed network", "ssid", currentNetwork.SSID, "bssid", currentNetwork.BSSID, "signal", currentNetwork.Signal, "freq", currentNetwork.Frequency, "security", currentNetwork.Security)
				}
			}
			currentNetwork = &types.WiFiNetwork{}
			currentSecurity = "Open" // Default to open
			if match := bssidRegex.FindStringSubmatch(line); len(match) > 1 {
				currentNetwork.BSSID = match[1]
				if m.logger != nil {
					m.logger.Debug("Found BSSID", "bssid", match[1])
				}
			}
		} else if strings.HasPrefix(line, "SSID: ") {
			if match := ssidRegex.FindStringSubmatch(line); len(match) > 1 {
				currentNetwork.SSID = strings.TrimSpace(match[1])
				currentNetwork.SSID = m.decodeSSID(currentNetwork.SSID)
				if m.logger != nil {
					m.logger.Debug("Found SSID", "ssid", match[1])
				}
			}
		} else if strings.HasPrefix(line, "signal: ") {
			if match := signalRegex.FindStringSubmatch(line); len(match) > 1 {
				if m.logger != nil {
					m.logger.Debug("Signal match", "raw", match[1])
				}
				if signal, err := strconv.ParseFloat(match[1], 64); err == nil {
					currentNetwork.Signal = int(signal)
					if m.logger != nil {
						m.logger.Debug("Parsed signal", "signal", signal)
					}
				} else {
					if m.logger != nil {
						m.logger.Warn("Failed to parse signal", "raw", match[1], "error", err)
					}
				}
			}
		} else if strings.HasPrefix(line, "freq: ") {
			if match := freqRegex.FindStringSubmatch(line); len(match) > 1 {
				if freq, err := strconv.Atoi(match[1]); err == nil {
					currentNetwork.Frequency = freq
					if m.logger != nil {
						m.logger.Debug("Parsed freq", "freq", freq)
					}
				}
			}
		} else if strings.Contains(line, "RSN:") {
			// WPA2 or WPA3
			if strings.Contains(line, "Authentication suites: SAE") {
				currentSecurity = "WPA3"
			} else {
				currentSecurity = "WPA2"
			}
		} else if strings.Contains(line, "WPA:") {
			currentSecurity = "WPA"
		} else if strings.Contains(line, "WEP:") {
			currentSecurity = "WEP"
		}
	}

	if currentNetwork != nil && currentNetwork.SSID != "" {
		currentNetwork.Security = currentSecurity
		if existing, ok := networksMap[currentNetwork.SSID]; !ok || currentNetwork.Signal > existing.Signal {
			networksMap[currentNetwork.SSID] = currentNetwork
		}
	}

	var networks []types.WiFiNetwork
	for _, net := range networksMap {
		networks = append(networks, *net)
	}

	// Sort networks by signal strength (strongest first)
	// Since dBm values are negative, higher values (closer to 0) are stronger
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Signal > networks[j].Signal
	})

	return networks, nil
}

// escapeWPAString escapes special characters for wpa_supplicant config values
// This prevents injection attacks via specially crafted SSIDs/passwords
func escapeWPAString(s string) string {
	// Escape backslashes first (must be done before escaping quotes)
	s = strings.ReplaceAll(s, `\`, `\\`)
	// Escape double quotes
	s = strings.ReplaceAll(s, `"`, `\"`)
	// Escape newlines to prevent config injection
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// isValidBSSID validates that a BSSID is in the correct format (XX:XX:XX:XX:XX:XX)
// This prevents config injection attacks via malformed BSSID values
func isValidBSSID(bssid string) bool {
	return validBSSIDRegex.MatchString(bssid)
}

func (m *Manager) generateWPAConfig(ssid, password string, bssid string) string {
	// Escape SSID and password to prevent injection
	escapedSSID := escapeWPAString(ssid)

	// Validate BSSID format to prevent config injection
	// Invalid BSSIDs are silently ignored (connection will work without pinning)
	validatedBSSID := ""
	if bssid != "" && isValidBSSID(bssid) {
		validatedBSSID = strings.ToLower(bssid) // Normalize to lowercase
	} else if bssid != "" {
		m.logger.Warn("Invalid BSSID format, ignoring", "bssid", bssid)
	}

	// ctrl_interface is required for wpa_cli communication
	header := "ctrl_interface=/run/wpa_supplicant\n\n"

	if password == "" {
		// Open network
		config := header + fmt.Sprintf(`network={
	ssid="%s"
	key_mgmt=NONE`, escapedSSID)
		if validatedBSSID != "" {
			config += fmt.Sprintf("\n\tbssid=%s", validatedBSSID)
		}
		config += "\n}"
		return config
	}

	// WPA2 network
	escapedPassword := escapeWPAString(password)
	config := header + fmt.Sprintf(`network={
	ssid="%s"
	psk="%s"`, escapedSSID, escapedPassword)
	if validatedBSSID != "" {
		config += fmt.Sprintf("\n\tbssid=%s", validatedBSSID)
	}
	config += "\n}"
	return config
}

func (m *Manager) obtainDHCP(hostname string) error {
	return m.dhcpClient.Acquire(m.iface, hostname)
}

func (m *Manager) parseIPAddress(output string) net.IP {
	return system.ParseIPFromOutput(output)
}

func (m *Manager) parseGateway(output string) net.IP {
	return system.ParseGatewayFromOutput(output)
}

func (m *Manager) getCurrentSSID() (string, error) {
	// Use 2s timeout - this is a simple query that completes in <100ms
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "iw", m.iface, "link")
	if err != nil {
		return "", err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSID: ") {
			ssid := strings.TrimPrefix(line, "SSID: ")
			return m.decodeSSID(ssid), nil
		}
	}
	return "", fmt.Errorf("SSID not found")
}

func (m *Manager) getDNSServers() ([]net.IP, error) {
	output, err := m.readFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return system.ParseDNSFromResolvConf(output), nil
}
func (m *Manager) decodeSSID(ssid string) string {
	// Use package-level compiled regex for better performance
	result := hexEscapeRegex.ReplaceAllStringFunc(ssid, func(match string) string {
		hex := match[2:] // remove \x
		b, err := strconv.ParseUint(hex, 16, 8)
		if err != nil {
			return match // if invalid, keep as is
		}
		return string(byte(b))
	})
	return result
}

// writeFile writes content to a file with secure permissions (0600)
// Uses install command to atomically create file with correct permissions
// avoiding TOCTOU race where file exists briefly with wrong permissions
func (m *Manager) writeFile(path, content string) error {
	return system.WriteSecureFile(m.executor, path, content)
}

func (m *Manager) readFile(path string) (string, error) {
	// Use 2s timeout - file reads complete in <10ms
	return m.executor.ExecuteWithTimeout(2*time.Second, "cat", path)
}

// killProcess kills processes matching a pattern with SIGKILL (fast, no graceful shutdown)
// DEPRECATED: Use terminateWpaSupplicant or terminateDhclient for interface-specific termination
func (m *Manager) killProcess(pattern string) {
	system.KillProcessFast(m.executor, m.logger, pattern)
}

// terminateWpaSupplicant terminates wpa_supplicant for this interface only
// Uses wpa_cli terminate for graceful shutdown, with pkill fallback
func (m *Manager) terminateWpaSupplicant() {
	// Try graceful termination via wpa_cli (interface-specific)
	_, err := m.executor.ExecuteWithTimeout(2*time.Second, "wpa_cli", "-i", m.iface, "terminate")
	if err != nil {
		// Fallback to interface-specific pkill
		// Pattern matches: wpa_supplicant ... -i <interface> ...
		m.executor.ExecuteWithTimeout(500*time.Millisecond,
			"pkill", "-9", "-f", fmt.Sprintf("wpa_supplicant.*-i[[:space:]]+%s", m.iface))
	}
}

// terminateDhclient terminates dhclient for this interface only
func (m *Manager) terminateDhclient() {
	// Interface-specific pkill
	// Pattern matches: dhclient ... <interface> (interface is typically last arg)
	m.executor.ExecuteWithTimeout(500*time.Millisecond,
		"pkill", "-9", "-f", fmt.Sprintf("dhclient.*%s", m.iface))
}

// waitForWpaSupplicantReady polls until wpa_supplicant responds to wpa_cli
// Returns true if ready within timeout, false otherwise
func (m *Manager) waitForWpaSupplicantReady(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	pollInterval := 50 * time.Millisecond // Fast polling since wpa_supplicant is usually quick

	for time.Now().Before(deadline) {
		// wpa_cli status returns 0 when wpa_supplicant is responsive
		// Use 2s timeout - wpa_cli typically responds in <100ms
		_, err := m.executor.ExecuteWithTimeout(2*time.Second, "wpa_cli", "-i", m.iface, "status")
		if err == nil {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

func (m *Manager) waitForAssociation(expectedSSID string) error {
	timeout := m.associationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Try event-based waiting first (faster)
	err := m.waitForAssociationEvents(expectedSSID, timeout)
	if err == nil {
		return nil
	}

	// Event-based failed (likely wpa_cli doesn't support wait_event), fall back to polling
	m.logger.Debug("Event-based association wait failed, using polling", "error", err)
	return m.waitForAssociationPolling(expectedSSID, timeout)
}

// waitForAssociationEvents uses wpa_cli wait_event for instant notification
func (m *Manager) waitForAssociationEvents(expectedSSID string, timeout time.Duration) error {
	// wpa_cli wait_event blocks until one of the specified events occurs
	// This is much faster than polling as we get notified immediately
	output, err := m.executor.ExecuteWithTimeout(timeout, "wpa_cli", "-i", m.iface,
		"wait_event", "CTRL-EVENT-CONNECTED", "CTRL-EVENT-ASSOC-REJECT",
		"CTRL-EVENT-DISCONNECTED", "CTRL-EVENT-TEMP-DISABLED", "CTRL-EVENT-AUTH-REJECT")

	if err != nil {
		return fmt.Errorf("wait_event failed: %w", err)
	}

	// Check which event we received
	if strings.Contains(output, "CTRL-EVENT-CONNECTED") {
		m.logger.Debug("Successfully associated with access point (event)", "ssid", expectedSSID)
		return nil
	}

	// Any other event is a failure
	if strings.Contains(output, "CTRL-EVENT-ASSOC-REJECT") {
		return fmt.Errorf("association rejected")
	}
	if strings.Contains(output, "CTRL-EVENT-AUTH-REJECT") {
		return fmt.Errorf("authentication rejected")
	}
	if strings.Contains(output, "CTRL-EVENT-TEMP-DISABLED") {
		return fmt.Errorf("network temporarily disabled (wrong password?)")
	}
	if strings.Contains(output, "CTRL-EVENT-DISCONNECTED") {
		return fmt.Errorf("disconnected during association")
	}

	return fmt.Errorf("unexpected event: %s", output)
}

// waitForAssociationPolling uses polling as a fallback
func (m *Manager) waitForAssociationPolling(expectedSSID string, timeout time.Duration) error {
	timeoutCh := time.After(timeout)
	// Use 300ms poll interval - balances responsiveness with overhead
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCh:
			return fmt.Errorf("timeout waiting for association to %s", expectedSSID)
		case <-ticker.C:
			// Use wpa_cli status which is faster than iw link
			if m.isAssociatedWpaCli(expectedSSID) {
				m.logger.Debug("Successfully associated with access point", "ssid", expectedSSID)
				return nil
			}
		}
	}
}

// isAssociatedWpaCli checks association status using wpa_cli (faster than iw)
func (m *Manager) isAssociatedWpaCli(expectedSSID string) bool {
	// Use 2s timeout - wpa_cli typically responds in <100ms
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "wpa_cli", "-i", m.iface, "status")
	if err != nil {
		return false
	}

	var ssidMatch, stateCompleted bool
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssid=") {
			ssid := strings.TrimPrefix(line, "ssid=")
			ssidMatch = (ssid == expectedSSID)
		}
		if line == "wpa_state=COMPLETED" {
			stateCompleted = true
		}
	}

	return ssidMatch && stateCompleted
}

func (m *Manager) hasValidIP() bool {
	// Check if interface has a valid IP address
	output, err := m.executor.Execute("ip", "addr", "show", m.iface)
	if err != nil {
		return false
	}

	// Look for an inet address that's not localhost
	ip := m.parseIPAddress(output)
	if ip == nil {
		return false
	}

	// Check it's not a link-local address (169.254.x.x)
	if ip.IsLinkLocalUnicast() {
		m.logger.Debug("Interface has link-local IP only (DHCP likely failed)", "ip", ip.String())
		return false
	}

	// Check it's not loopback
	if ip.IsLoopback() {
		return false
	}

	return true
}

func (m *Manager) checkCaptivePortal() bool {
	// Try to ping a known public DNS server
	_, err := m.executor.Execute("ping", "-c", "1", "-W", "2", "8.8.8.8")
	if err != nil {
		// If ping fails, try to resolve a domain using getent (more portable than nslookup)
		_, err = m.executor.Execute("getent", "hosts", "google.com")
		if err != nil {
			// Alternative: try with dig if getent is not available
			_, err = m.executor.Execute("dig", "+short", "google.com")
			if err != nil {
				m.logger.Warn("Captive portal detected. To trigger the portal redirect, open a browser to http://neverssl.com")
				return true // Likely captive portal
			}
		}
	}
	return false
}
