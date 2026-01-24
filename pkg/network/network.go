package network

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// Manager implements the NetworkManager interface
type Manager struct {
	executor   types.SystemExecutor
	logger     types.Logger
	dhcpClient types.DHCPClientManager
}

// NewManager creates a new network manager
func NewManager(executor types.SystemExecutor, logger types.Logger, dhcpClient types.DHCPClientManager) *Manager {
	return &Manager{
		executor:   executor,
		logger:     logger,
		dhcpClient: dhcpClient,
	}
}

// killProcess kills processes matching a pattern with SIGKILL (fast, no graceful shutdown)
func (m *Manager) killProcess(pattern string) {
	system.KillProcessFast(m.executor, m.logger, pattern)
}

// SetDNS configures DNS servers
func (m *Manager) SetDNS(servers []string) error {
	if len(servers) == 0 || (len(servers) == 1 && servers[0] == "dhcp") {
		// Remove immutable flag to allow DHCP to update DNS
		_, err := m.executor.Execute("chattr", "-i", "/etc/resolv.conf")
		if err != nil {
			m.logger.Debug("Failed to remove immutable flag (may not be set)", "error", err)
		}
		m.logger.Info("Using DHCP for DNS configuration")
		return nil
	}

	m.logger.Info("Setting DNS servers", "servers", servers)

	// Write to /etc/resolv.conf
	var resolvConf strings.Builder
	for _, server := range servers {
		if net.ParseIP(server) != nil {
			resolvConf.WriteString(fmt.Sprintf("nameserver %s\n", server))
		}
	}

	// Use chattr to make file immutable temporarily
	_, err := m.executor.Execute("chattr", "-i", "/etc/resolv.conf")
	if err != nil {
		m.logger.Warn("Failed to remove immutable flag from resolv.conf", "error", err)
	}

	err = m.writeFile("/etc/resolv.conf", resolvConf.String())
	if err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	// Make immutable again
	_, err = m.executor.Execute("chattr", "+i", "/etc/resolv.conf")
	if err != nil {
		m.logger.Warn("Failed to set immutable flag on resolv.conf", "error", err)
	}

	return nil
}

// ClearDNS clears the DNS configuration by removing /etc/resolv.conf
func (m *Manager) ClearDNS() error {
	m.logger.Debug("Clearing DNS configuration")

	// Remove immutable flag if set
	_, err := m.executor.Execute("chattr", "-i", "/etc/resolv.conf")
	if err != nil {
		m.logger.Debug("Failed to remove immutable flag from resolv.conf", "error", err)
	}

	// Clear the file by writing an empty configuration
	err = m.writeFile("/etc/resolv.conf", "# DNS cleared by net\n")
	if err != nil {
		return fmt.Errorf("failed to clear resolv.conf: %w", err)
	}

	m.logger.Debug("DNS configuration cleared")
	return nil
}

// SetMAC sets the MAC address for an interface
func (m *Manager) SetMAC(iface, mac string) error {
	m.logger.Debug("SetMAC using interface", "interface", iface, "mac", mac)

	// Validate interface name
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	if mac == "" || mac == "random" {
		mac = m.generateRandomMAC()
	}

	if mac == "default" {
		// Use a default MAC (random MacBook Pro style)
		mac = m.generateMacBookProMAC()
	}

	if mac == "permanent" {
		// Restore the factory/permanent MAC address
		permMAC, err := m.getPermanentMAC(iface)
		if err != nil {
			return fmt.Errorf("failed to get permanent MAC: %w", err)
		}
		mac = permMAC
	}

	// Handle MAC templates like "00:??:??:??:??:??"
	if strings.Contains(mac, "??") {
		mac = m.expandMACTemplate(mac)
	}

	// Validate final MAC address format
	if err := types.ValidateMAC(mac); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	m.logger.Info("Setting MAC address", "interface", iface, "mac", mac)

	// Bring interface down
	_, err := m.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", iface, "down")
	if err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Set MAC address
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", iface, "address", mac)
	if err != nil {
		return fmt.Errorf("failed to set MAC address: %w", err)
	}

	// Bring interface up
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", iface, "up")
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// GetMAC gets the current MAC address
func (m *Manager) GetMAC(iface string) (string, error) {
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "show", iface)
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w", err)
	}

	// Parse MAC from output like: "link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "link/ether") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("MAC address not found in interface output")
}

// SetIP sets IP address and gateway
func (m *Manager) SetIP(iface, addr, gateway string) error {
	m.logger.Info("Setting IP configuration", "interface", iface, "addr", addr, "gateway", gateway)
	m.logger.Debug("SetIP using wireless interface", "interface", iface)

	// Flush existing addresses
	_, err := m.executor.ExecuteWithTimeout(5*time.Second, "ip", "addr", "flush", "dev", iface)
	if err != nil {
		m.logger.Warn("Failed to flush addresses", "error", err)
	}

	if addr != "" {
		// Add IP address
		_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "addr", "add", addr, "dev", iface)
		if err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	if gateway != "" {
		// Add default route
		_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "add", "default", "via", gateway, "dev", iface)
		if err != nil {
			return fmt.Errorf("failed to set gateway: %w", err)
		}
	}

	return nil
}

// AddRoute adds a custom route
func (m *Manager) AddRoute(iface, destination, gateway string) error {
	m.logger.Info("Adding route", "destination", destination, "gateway", gateway, "interface", iface)

	_, err := m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "add", destination, "via", gateway, "dev", iface)
	return err
}

// FlushRoutes removes all routes
func (m *Manager) FlushRoutes(iface string) error {
	m.logger.Info("Flushing routes", "interface", iface)

	_, err := m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "flush", "dev", iface)
	return err
}

// SetHostname sets the system hostname
func (m *Manager) SetHostname(hostname string) error {
	if hostname == "" {
		m.logger.Debug("No hostname to set")
		return nil
	}

	m.logger.Info("Setting hostname", "hostname", hostname)

	// Update /etc/hosts FIRST to include the new hostname (required for sudo to work)
	// This must happen before the hostname command, otherwise sudo fails with
	// "unable to resolve host" between the hostname change and hosts update.
	hostsContent, err := m.executor.Execute("cat", "/etc/hosts")
	if err != nil {
		m.logger.Warn("Failed to read /etc/hosts", "error", err)
	} else {
		// Check if we need to update the localhost entry
		lines := strings.Split(hostsContent, "\n")
		var newLines []string
		hostnameAdded := false

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Update 127.0.1.1 line (Debian/Ubuntu style hostname entry)
			if strings.HasPrefix(trimmed, "127.0.1.1") {
				newLines = append(newLines, fmt.Sprintf("127.0.1.1\t%s", hostname))
				hostnameAdded = true
			} else {
				newLines = append(newLines, line)
			}
		}

		// If no 127.0.1.1 entry existed, add one after 127.0.0.1 localhost
		if !hostnameAdded {
			var finalLines []string
			for _, line := range newLines {
				finalLines = append(finalLines, line)
				if strings.Contains(line, "127.0.0.1") && strings.Contains(line, "localhost") {
					finalLines = append(finalLines, fmt.Sprintf("127.0.1.1\t%s", hostname))
					hostnameAdded = true
				}
			}
			if hostnameAdded {
				newLines = finalLines
			}
		}

		// Write updated hosts file
		newHostsContent := strings.Join(newLines, "\n")
		_, err = m.executor.ExecuteWithInput("tee", newHostsContent, "/etc/hosts")
		if err != nil {
			m.logger.Warn("Failed to update /etc/hosts", "error", err)
		} else {
			m.logger.Debug("Updated /etc/hosts with new hostname")
		}
	}

	// Now set the hostname (after /etc/hosts is updated)
	_, err = m.executor.Execute("hostname", hostname)
	if err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}

	// Also update /etc/hostname for persistence
	_, err = m.executor.ExecuteWithInput("tee", hostname+"\n", "/etc/hostname")
	if err != nil {
		m.logger.Warn("Failed to update /etc/hostname", "error", err)
	}

	return nil
}

// StartDHCP performs initial DHCP lease acquisition
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname
func (m *Manager) StartDHCP(iface string, hostname string) error {
	return m.dhcpClient.Acquire(iface, hostname)
}

// DHCPRenew performs DHCP renewal
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname
func (m *Manager) DHCPRenew(iface string, hostname string) error {
	return m.dhcpClient.Renew(iface, hostname)
}

// detectInterface detects the appropriate network interface for the given configuration
func (m *Manager) detectInterface(config *types.NetworkConfig) string {
	if config.Interface != "" {
		m.logger.Debug("Using configured interface", "interface", config.Interface)
		return config.Interface
	}

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		m.logger.Error("Failed to get network interfaces", "error", err)
		return ""
	}

	var candidates []string
	if config.SSID != "" {
		// Wireless connection - look for wireless interfaces
		// Patterns: wlan* (traditional), wlp* (systemd predictable), ath* (Atheros),
		// ra* (Ralink), wcn* (some ARM SoCs), mlan* (Marvell)
		m.logger.Debug("Detecting wireless interface for SSID", "ssid", config.SSID)
		for _, iface := range ifaces {
			name := iface.Name
			if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlp") ||
				strings.HasPrefix(name, "ath") || strings.HasPrefix(name, "ra") ||
				strings.HasPrefix(name, "wcn") || strings.HasPrefix(name, "mlan") {
				candidates = append(candidates, name)
				m.logger.Debug("Found wireless interface candidate", "interface", name)
			}
		}
	} else {
		// Wired connection - look for wired interfaces
		// Patterns: eth* (traditional), enp* (systemd PCI), enx* (systemd MAC),
		// eno* (systemd onboard), ens* (systemd slot), em* (Dell/BSD-style),
		// usb* (USB ethernet adapters)
		m.logger.Debug("Detecting wired interface")
		for _, iface := range ifaces {
			name := iface.Name
			if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "enp") ||
				strings.HasPrefix(name, "enx") || strings.HasPrefix(name, "eno") ||
				strings.HasPrefix(name, "ens") || strings.HasPrefix(name, "em") ||
				strings.HasPrefix(name, "usb") {
				candidates = append(candidates, name)
				m.logger.Debug("Found wired interface candidate", "interface", name)
			}
		}
	}

	if len(candidates) == 0 {
		m.logger.Warn("No suitable interface found")
		return ""
	}

	// For wired interfaces, prefer interfaces with carrier (cable plugged in)
	if config.SSID == "" {
		for _, candidate := range candidates {
			// Check carrier status
			carrier, err := m.executor.Execute("cat", "/sys/class/net/"+candidate+"/carrier")
			if err == nil && strings.TrimSpace(carrier) == "1" {
				m.logger.Info("Detected wired interface with carrier", "interface", candidate)
				return candidate
			}
		}
		// No interface with carrier found, try bringing them up and polling for carrier
		m.logger.Debug("No interface with carrier found, trying to bring interfaces up")
		for _, candidate := range candidates {
			// Bring interface up
			_, err := m.executor.Execute("ip", "link", "set", candidate, "up")
			if err != nil {
				m.logger.Debug("Failed to bring up interface", "interface", candidate, "error", err)
				continue
			}
			// Poll for carrier detection (up to 3 seconds, 100ms intervals)
			if m.waitForCarrier(candidate, 3*time.Second) {
				m.logger.Info("Detected wired interface with carrier after bringing up", "interface", candidate)
				return candidate
			}
		}
		// Still no carrier, return first candidate as fallback
		m.logger.Warn("No wired interface with carrier detected, using first candidate", "interface", candidates[0])
	}

	// Return the first candidate (interfaces are typically ordered consistently)
	detected := candidates[0]
	m.logger.Info("Detected interface", "interface", detected, "type", map[bool]string{true: "wireless", false: "wired"}[config.SSID != ""])
	return detected
}

// Helper functions

func (m *Manager) findWirelessInterface() (string, error) {
	output, err := m.executor.Execute("iw", "dev")
	if err != nil {
		m.logger.Debug("Failed to list wireless devices", "error", err)
		return "", fmt.Errorf("failed to list wireless devices: %w", err)
	}

	// Parse output to find interface name
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			iface := strings.TrimPrefix(line, "Interface ")
			m.logger.Debug("Found wireless interface", "interface", iface)
			return iface, nil
		}
	}

	m.logger.Debug("No wireless interface found")
	return "", fmt.Errorf("no wireless interface found")
}

func (m *Manager) generateRandomMAC() string {
	// Use crypto/rand for secure random bytes
	mac := make([]byte, 6)
	_, err := rand.Read(mac)
	if err != nil {
		m.logger.Warn("Failed to generate random MAC, using fallback", "error", err)
		// Fallback to simple pattern
		return "02:00:00:00:00:01"
	}
	// Set local bit and clear multicast bit (makes it a valid unicast local MAC)
	mac[0] = (mac[0] | 0x02) & 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (m *Manager) generateMacBookProMAC() string {
	// Random MacBook Pro MAC (Apple OUI: AC:BC:32)
	mac := make([]byte, 3)
	_, err := rand.Read(mac)
	if err != nil {
		m.logger.Warn("Failed to generate random MAC, using fallback", "error", err)
		return "ac:bc:32:00:00:01"
	}
	return fmt.Sprintf("ac:bc:32:%02x:%02x:%02x", mac[0], mac[1], mac[2])
}

func (m *Manager) expandMACTemplate(template string) string {
	result := template
	for strings.Contains(result, "??") {
		randomByte := make([]byte, 1)
		_, err := rand.Read(randomByte)
		if err != nil {
			randomByte[0] = 0x00 // Fallback
		}
		result = strings.Replace(result, "??", fmt.Sprintf("%02x", randomByte[0]), 1)
	}
	return result
}

// getPermanentMAC retrieves the factory/permanent MAC address using ethtool
func (m *Manager) getPermanentMAC(iface string) (string, error) {
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "ethtool", "-P", iface)
	if err != nil {
		return "", fmt.Errorf("ethtool not available or failed: %w", err)
	}
	// Parse "Permanent address: aa:bb:cc:dd:ee:ff"
	output = strings.TrimSpace(output)
	parts := strings.Split(output, ": ")
	if len(parts) == 2 {
		mac := strings.TrimSpace(parts[1])
		// Validate the MAC format
		if err := types.ValidateMAC(mac); err != nil {
			return "", fmt.Errorf("invalid MAC from ethtool: %s", mac)
		}
		return mac, nil
	}
	return "", fmt.Errorf("could not parse permanent MAC from: %s", output)
}

func (m *Manager) writeFile(path, content string) error {
	// Use a simple echo to file approach since we don't have direct file writing
	// In a real implementation, you'd want proper file permissions handling
	tempFile := types.RuntimeDir + "/staging.conf"
	// Remove temp file before writing to prevent permission errors
	_, err := m.executor.Execute("rm", "-f", tempFile)
	if err != nil {
		m.logger.Warn("Failed to remove temp file", "error", err)
	}
	err = m.writeFileDirect(tempFile, content)
	if err != nil {
		return err
	}

	_, err = m.executor.Execute("mv", tempFile, path)
	return err
}

func (m *Manager) writeFileDirect(path, content string) error {
	// This is a simplified version. In production, use proper file I/O
	_, err := m.executor.ExecuteWithInput("tee", content, path)
	return err
}

// waitForCarrier polls for carrier detection on an interface
// Returns true if carrier is detected within the timeout, false otherwise
func (m *Manager) waitForCarrier(iface string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	pollInterval := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		carrier, err := m.executor.Execute("cat", "/sys/class/net/"+iface+"/carrier")
		if err == nil && strings.TrimSpace(carrier) == "1" {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

func (m *Manager) parseIPAddress(output string) net.IP {
	return system.ParseIPFromOutput(output)
}

// ConnectToConfiguredNetwork connects to a network based on the provided configuration
func (m *Manager) ConnectToConfiguredNetwork(config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
	// Detect interface if not configured
	if config.Interface == "" {
		config.Interface = m.detectInterface(config)
		if config.Interface == "" {
			return fmt.Errorf("no suitable interface detected for network configuration")
		}
	}

	m.logger.Debug("Connecting to configured network", "interface", config.Interface, "ssid", config.SSID, "addr", config.Addr)

	// CRITICAL: Apply MAC address BEFORE bringing interface up or connecting
	if config.MAC != "" {
		m.logger.Debug("Setting MAC address from config (before connection)", "mac", config.MAC)
		err := m.SetMAC(config.Interface, config.MAC)
		if err != nil {
			return fmt.Errorf("failed to set MAC: %w", err)
		}
	}

	// Note: Hostname is NOT set on the system, but will be sent in DHCP requests
	// This prevents changing the local system hostname while still identifying to DHCP servers
	if config.Hostname != "" {
		m.logger.Debug("Will send hostname in DHCP request", "hostname", config.Hostname)
	}

	// Check if we should use DHCP for DNS - if so, unlock resolv.conf BEFORE DHCP runs
	// so the DHCP client can write DNS servers from the DHCP response.
	// This applies when: dns: dhcp is set, OR no DNS is configured at all (let DHCP handle it)
	useDHCPForDNS := config.DNS == nil || len(config.DNS) == 0 || (len(config.DNS) == 1 && config.DNS[0] == "dhcp")
	if useDHCPForDNS {
		m.logger.Debug("Unlocking resolv.conf for DHCP DNS")
		_, err := m.executor.Execute("chattr", "-i", "/etc/resolv.conf")
		if err != nil {
			m.logger.Debug("Failed to unlock resolv.conf (may not be locked)", "error", err)
		}
	}

	// Connect to WiFi if SSID is specified
	if config.SSID != "" {
		m.logger.Debug("Connecting to WiFi from config", "ssid", config.SSID, "apAddr", config.ApAddr)
		if password == "" {
			password = config.PSK
		}
		if config.WPA != "" {
			// Use WPA config - will be handled by enhanced wifiMgr in future
			m.logger.Warn("Custom WPA configuration not fully implemented, using PSK")
		}
		m.logger.Info("Connecting to SSID", "ssid", config.SSID)

		// Use BSSID pinning if ap-addr is configured
		if config.ApAddr != "" {
			m.logger.Info("Using AP address pinning", "bssid", config.ApAddr)
			err := wifiMgr.ConnectWithBSSID(config.SSID, password, config.ApAddr, config.Hostname)
			if err != nil {
				return fmt.Errorf("failed to connect to WiFi: %w", err)
			}
		} else {
			err := wifiMgr.Connect(config.SSID, password, config.Hostname)
			if err != nil {
				return fmt.Errorf("failed to connect to WiFi: %w", err)
			}
		}
	} else {
		m.logger.Debug("No SSID specified in network config - treating as wired connection")
		// For wired connections, bring up the interface and get DHCP if no static IP
		if config.Interface != "" {
			m.logger.Info("Bringing up wired interface", "interface", config.Interface)
			_, err := m.executor.Execute("ip", "link", "set", config.Interface, "up")
			if err != nil {
				m.logger.Warn("Failed to bring up wired interface", "interface", config.Interface, "error", err)
			}

			// Wait for link carrier before starting DHCP (poll up to 5 seconds)
			if !m.waitForCarrier(config.Interface, 5*time.Second) {
				m.logger.Warn("No carrier detected on interface, proceeding anyway", "interface", config.Interface)
			}

			if config.Addr == "" {
				m.logger.Info("Obtaining DHCP lease on wired interface", "interface", config.Interface)
				err := m.StartDHCP(config.Interface, config.Hostname)
				if err != nil {
					m.logger.Warn("Failed to obtain DHCP on wired interface", "interface", config.Interface, "error", err)
				}
			}
		}
	}

	// Set static IP if configured
	if config.Addr != "" {
		m.logger.Debug("Setting static IP from config", "addr", config.Addr, "gateway", config.Gateway)
		err := m.SetIP(config.Interface, config.Addr, config.Gateway)
		if err != nil {
			return fmt.Errorf("failed to set IP: %w", err)
		}
	}

	// Add routes - handle "default" keyword
	for _, route := range config.Routes {
		m.logger.Debug("Adding route from config", "route", route)

		// Handle "default" keyword
		if strings.TrimSpace(route) == "default" {
			m.logger.Debug("Skipping 'default' route - already handled by gateway")
			continue
		}

		parts := strings.Split(route, " -> ")
		if len(parts) == 2 {
			destination := strings.TrimSpace(parts[0])
			gateway := strings.TrimSpace(parts[1])
			err := m.AddRoute(config.Interface, destination, gateway)
			if err != nil {
				m.logger.Warn("Failed to add route", "route", route, "error", err)
			}
		} else {
			m.logger.Warn("Invalid route format, expected 'destination -> gateway'", "route", route)
		}
	}

	// Apply DNS AFTER DHCP completes (to override DHCP-provided DNS)
	if config.DNS != nil && len(config.DNS) > 0 {
		// Check if DNS is "dhcp" - if so, skip manual DNS setting
		if len(config.DNS) == 1 && config.DNS[0] == "dhcp" {
			m.logger.Debug("Using DHCP-provided DNS")
		} else {
			m.logger.Debug("Setting custom DNS from config (after connection)", "dns", config.DNS)
			err := m.SetDNS(config.DNS)
			if err != nil {
				m.logger.Warn("Failed to set DNS", "error", err)
			}
		}
	}

	return nil
}

// GetConnectionInfo retrieves connection information for the specified interface
func (m *Manager) GetConnectionInfo(iface string) (*types.Connection, error) {
	m.logger.Debug("Getting connection info", "interface", iface)

	// Get IP address
	ipOutput, err := m.executor.Execute("ip", "addr", "show", iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses: %w", err)
	}
	ip := m.parseIPAddress(ipOutput)

	// Get gateway
	routeOutput, err := m.executor.Execute("ip", "route", "show", "dev", iface)
	if err != nil {
		m.logger.Debug("Failed to get routes", "error", err)
	}
	gateway := m.parseGateway(routeOutput)

	// Get DNS servers
	dns, err := m.getDNSServers()
	if err != nil {
		m.logger.Debug("Failed to get DNS servers", "error", err)
	}

	return &types.Connection{
		Interface: iface,
		State:     "connected",
		IP:        ip,
		Gateway:   gateway,
		DNS:       dns,
	}, nil
}

// parseGateway extracts the default gateway from ip route output
func (m *Manager) parseGateway(output string) net.IP {
	return system.ParseGatewayFromOutput(output)
}

// getDNSServers reads DNS servers from /etc/resolv.conf
func (m *Manager) getDNSServers() ([]net.IP, error) {
	output, err := m.executor.Execute("cat", "/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return system.ParseDNSFromResolvConf(output), nil
}
