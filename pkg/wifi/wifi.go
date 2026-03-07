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

	// Always trigger a fresh scan — cached results from scan dump may only
	// contain the currently connected AP when connected to a network
	_, err = m.executor.ExecuteWithTimeout(10*time.Second, "iw", m.iface, "scan")
	if err != nil {
		m.logger.Warn("Fresh scan failed, falling back to cached results", "error", err)
	}

	// Read scan results (includes results from fresh scan above)
	output, err := m.executor.ExecuteWithTimeout(5*time.Second, "iw", m.iface, "scan", "dump")
	if err != nil {
		return nil, fmt.Errorf("failed to get scan results: %w", err)
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

	// Detect AP security type from cached scan results to generate the correct
	// wpa_supplicant config (WPA3 needs SAE key_mgmt and required PMF)
	security := m.detectNetworkSecurity(ssid)
	if security != "" {
		m.logger.Debug("Detected AP security type", "ssid", ssid, "security", security)
	}

	// Reject WEP networks - insecure and not supported
	if security == "WEP" {
		return fmt.Errorf("WEP networks are not supported: WEP encryption is broken and insecure, use WPA2 or WPA3 instead")
	}

	// Warn if AP requires encryption but no password was provided
	if password == "" && (security == "WPA3" || security == "WPA2/WPA3" || security == "WPA2") {
		m.logger.Warn("Network requires encryption but no password provided - check config file (YAML '#' starts a comment, quote passwords containing '#')", "ssid", ssid, "security", security)
	}

	// Create wpa_supplicant config with optional BSSID pinning
	config := m.generateWPAConfig(ssid, password, bssid, security)
	// Don't log config - it contains credentials
	m.logger.Debug("Generated WPA config", "ssid", ssid, "hasBSSID", bssid != "", "security", security)

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
	// Clean up credentials file after wpa_supplicant reads it
	defer func() {
		_, _ = m.executor.Execute("rm", "-f", tempConfig)
	}()

	// Terminate existing wpa_supplicant for this interface only
	m.terminateWpaSupplicant()

	// Flush stale IP addresses and routes — after suspend/resume the old
	// network state remains on the interface even though the connection is dead.
	// Without this, DHCP may add a new IP but the default route won't be set.
	m.executor.Execute("ip", "addr", "flush", "dev", m.iface)
	m.executor.Execute("ip", "route", "flush", "dev", m.iface)

	// Bring interface up before starting wpa_supplicant
	_, err = m.executor.Execute("ip", "link", "set", m.iface, "up")
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Ensure wpa_supplicant control directory exists
	_, _ = m.executor.Execute("mkdir", "-p", "/run/wpa_supplicant")

	// Start wpa_supplicant — ctrl_interface is set in the config file,
	// don't also pass -C which can conflict and cause crashes with SAE.
	_, err = m.executor.Execute("wpa_supplicant", "-B", "-i", m.iface, "-c", tempConfig)
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
		if security == "WPA3" && strings.Contains(err.Error(), "crashed") {
			return fmt.Errorf("WPA3 (SAE) connection failed — wpa_supplicant crashed. Your wpa_supplicant may not support SAE. Check with: wpa_supplicant -h 2>&1 | grep SAE")
		}
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
	var inRSN bool

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "BSS ") {
			// Save previous network
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
			currentSecurity = "Open"
			inRSN = false
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
			inRSN = true
			currentSecurity = "WPA2" // default RSN = WPA2, may upgrade to WPA3
		} else if strings.Contains(line, "WPA:") {
			inRSN = false
			currentSecurity = "WPA"
		} else if strings.Contains(line, "WEP:") {
			inRSN = false
			currentSecurity = "WEP"
		} else if inRSN && strings.Contains(line, "Authentication suites:") {
			if strings.Contains(line, "SAE") && strings.Contains(line, "PSK") {
				currentSecurity = "WPA2/WPA3"
			} else if strings.Contains(line, "SAE") {
				currentSecurity = "WPA3"
			}
			// PSK-only stays as "WPA2" (set when RSN: was seen)
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

// detectNetworkSecurity determines the security type of a given SSID.
// Tries cached scan results first (fast), falls back to a fresh scan if
// the cache is empty (e.g. after interface was cycled for MAC change).
// Returns "WPA3", "WPA2/WPA3", "WPA2", or "" if not found.
func (m *Manager) detectNetworkSecurity(ssid string) string {
	// Try cached results first (instant)
	if sec := m.findSecurityInScan(ssid, "iw", m.iface, "scan", "dump"); sec != "" {
		return sec
	}

	// Cache was empty or SSID not found — do a fresh scan.
	// This happens when the interface was cycled (e.g. MAC change) before connect.
	m.logger.Debug("Scan cache empty, running fresh scan for security detection")
	return m.findSecurityInScan(ssid, "iw", m.iface, "scan")
}

// findSecurityInScan runs the given iw scan command and returns the security
// type for the given SSID, or "" if not found.
func (m *Manager) findSecurityInScan(ssid string, cmd ...string) string {
	output, err := m.executor.ExecuteWithTimeout(10*time.Second, cmd[0], cmd[1:]...)
	if err != nil {
		m.logger.Debug("Scan failed during security detection", "error", err)
		return ""
	}
	networks, err := m.parseScanResults(output)
	if err != nil {
		m.logger.Debug("Failed to parse scan results for security detection", "error", err)
		return ""
	}
	for _, net := range networks {
		if net.SSID == ssid {
			return net.Security
		}
	}
	return ""
}

func (m *Manager) generateWPAConfig(ssid, password string, bssid string, security ...string) string {
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
	header := "ctrl_interface=/run/wpa_supplicant\n"

	if password == "" {
		// Open network
		config := header + fmt.Sprintf("\nnetwork={\n\tssid=\"%s\"\n\tkey_mgmt=NONE", escapedSSID)
		if validatedBSSID != "" {
			config += fmt.Sprintf("\n\tbssid=%s", validatedBSSID)
		}
		config += "\n}"
		return config
	}

	escapedPassword := escapeWPAString(password)
	sec := ""
	if len(security) > 0 {
		sec = security[0]
	}

	// SAE (WPA3) needs sae_pwe in the global section for driver compatibility.
	// sae_pwe=2 accepts both hunting-and-pecking and hash-to-element methods,
	// which is the most compatible mode across APs (some iPhone hotspots
	// only support hunting-and-pecking).
	// Include for all password-protected networks since the default case also
	// offers SAE when security type is unknown.
	header += "sae_pwe=2\n"

	var config string
	switch sec {
	case "WPA3":
		// WPA3-only: SAE authentication with required PMF.
		// scan_ssid=1 triggers active probing — needed for iPhone hotspots
		// which can behave like hidden networks when the hotspot screen isn't open.
		// proto=RSN and pairwise=CCMP are required for SAE.
		config = header + fmt.Sprintf("\nnetwork={\n\tssid=\"%s\"\n\tscan_ssid=1\n\tsae_password=\"%s\"\n\tkey_mgmt=SAE\n\tproto=RSN\n\tpairwise=CCMP\n\tgroup=CCMP\n\tieee80211w=2",
			escapedSSID, escapedPassword)
	case "WPA2/WPA3":
		// Transition mode: WPA-PSK-SHA256 works better than WPA-PSK for
		// mixed-mode APs that require management frame protection.
		config = header + fmt.Sprintf("\nnetwork={\n\tssid=\"%s\"\n\tscan_ssid=1\n\tpsk=\"%s\"\n\tsae_password=\"%s\"\n\tkey_mgmt=WPA-PSK-SHA256 SAE\n\tproto=RSN\n\tpairwise=CCMP\n\tgroup=CCMP\n\tieee80211w=1",
			escapedSSID, escapedPassword, escapedPassword)
	default:
		// WPA2 or unknown: offer WPA-PSK first (most compatible), then
		// WPA-PSK-SHA256 and SAE for transition/WPA3 APs.
		// WPA-PSK must be listed so pure WPA2 APs (which only advertise PSK)
		// can negotiate successfully.
		// ieee80211w=1 (optional PMF) allows both PMF and non-PMF APs.
		config = header + fmt.Sprintf("\nnetwork={\n\tssid=\"%s\"\n\tscan_ssid=1\n\tpsk=\"%s\"\n\tsae_password=\"%s\"\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256 SAE\n\tproto=RSN WPA\n\tpairwise=CCMP TKIP\n\tgroup=CCMP TKIP\n\tieee80211w=1",
			escapedSSID, escapedPassword, escapedPassword)
	}

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
	// Tell NetworkManager to stop managing this interface.
	// This prevents NM from restarting wpa_supplicant after we kill it.
	// Fails silently if nmcli is not installed (non-NM systems).
	m.executor.ExecuteWithTimeout(2*time.Second, "nmcli", "device", "set", m.iface, "managed", "no")

	// Try graceful termination via wpa_cli (interface-specific).
	// This reaches both standalone and system (D-Bus) wpa_supplicant instances.
	_, err := m.executor.ExecuteWithTimeout(2*time.Second, "wpa_cli", "-i", m.iface, "terminate")
	if err != nil {
		// Fallback: kill ALL wpa_supplicant processes.
		// The system wpa_supplicant (started via -u -s for D-Bus) doesn't use
		// -i flag, so interface-specific pkill won't match it.
		// We must kill it to avoid nl80211 "Match already configured" conflicts
		// that prevent our instance from creating its control socket.
		m.executor.ExecuteWithTimeout(500*time.Millisecond,
			"pkill", "-9", "wpa_supplicant")
	}

	// Give the process time to fully exit and release nl80211 resources
	time.Sleep(500 * time.Millisecond)

	// Remove stale control socket — after suspend/resume the old wpa_supplicant
	// process is gone but its socket file remains, causing the new instance to
	// fail with exit code 255
	m.executor.Execute("rm", "-f", fmt.Sprintf("/run/wpa_supplicant/%s", m.iface))
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

	const maxConsecutiveFailures = 5
	consecutiveFailures := 0

	for {
		select {
		case <-timeoutCh:
			return fmt.Errorf("timeout waiting for association to %s", expectedSSID)
		case <-ticker.C:
			associated, reachable := m.checkAssociationStatus(expectedSSID)
			if associated {
				m.logger.Debug("Successfully associated with access point", "ssid", expectedSSID)
				return nil
			}
			if !reachable {
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveFailures {
					return fmt.Errorf("wpa_supplicant crashed or is unreachable (control socket disappeared)")
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

// checkAssociationStatus returns (associated, wpaSupplicantReachable).
// associated is true when the SSID matches and wpa_state=COMPLETED.
// wpaSupplicantReachable is true when wpa_cli can communicate with wpa_supplicant.
func (m *Manager) checkAssociationStatus(expectedSSID string) (bool, bool) {
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "wpa_cli", "-i", m.iface, "status")
	if err != nil {
		return false, false
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

	return ssidMatch && stateCompleted, true
}

// isAssociatedWpaCli checks association status using wpa_cli (faster than iw)
func (m *Manager) isAssociatedWpaCli(expectedSSID string) bool {
	associated, _ := m.checkAssociationStatus(expectedSSID)
	return associated
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
