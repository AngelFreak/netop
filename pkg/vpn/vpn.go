package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"golang.org/x/crypto/curve25519"
)

// activeVPNFile is the path to the file tracking the currently active VPN
const activeVPNFile = types.RuntimeDir + "/active-vpn"

// curve25519Basepoint is the standard basepoint for X25519 key derivation
var curve25519Basepoint = [32]byte{9}

// Manager implements the VPNManager interface
type Manager struct {
	executor      types.SystemExecutor
	logger        types.Logger
	configMgr     types.ConfigManager
	endpointRoute string     // Stores the VPN endpoint IP for cleanup on disconnect
	mu            sync.Mutex // Protects endpointRoute from concurrent access
}

// NewManager creates a new VPN manager
func NewManager(executor types.SystemExecutor, logger types.Logger, configMgr types.ConfigManager) *Manager {
	return &Manager{
		executor:  executor,
		logger:    logger,
		configMgr: configMgr,
	}
}

// Connect connects to a VPN
func (m *Manager) Connect(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Connecting to VPN", "name", name)

	// Load VPN config from ConfigManager
	config, err := m.configMgr.GetVPNConfig(name)
	if err != nil {
		return fmt.Errorf("failed to load VPN config '%s': %w", name, err)
	}

	var connectErr error
	switch config.Type {
	case "openvpn":
		connectErr = m.connectOpenVPN(config)
	case "wireguard":
		connectErr = m.connectWireGuard(config)
	default:
		return fmt.Errorf("unsupported VPN type: %s", config.Type)
	}

	if connectErr != nil {
		return connectErr
	}

	// Record the active VPN name for status tracking
	if err := m.setActiveVPN(name); err != nil {
		m.logger.Debug("Failed to record active VPN", "error", err)
		// Non-fatal: connection succeeded, just status tracking won't work perfectly
	}

	return nil
}

// Disconnect disconnects from a VPN
func (m *Manager) Disconnect(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Disconnecting from VPN", "name", name)

	// Kill OpenVPN processes with SIGKILL fallback
	m.killProcess("openvpn")

	// Collect WireGuard interfaces to tear down
	wgInterfaces := []string{}

	// Check for running WireGuard interfaces
	wgOutput, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "show", "type", "wireguard")
	if err == nil && strings.TrimSpace(wgOutput) != "" {
		lines := strings.Split(wgOutput, "\n")
		for _, line := range lines {
			// Lines with interface names start with a number and contain the interface
			if strings.Contains(line, ":") && !strings.HasPrefix(strings.TrimSpace(line), "link") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					iface := strings.Trim(parts[1], ":")
					wgInterfaces = append(wgInterfaces, iface)
				}
			}
		}
	}

	// If no WireGuard interfaces found, default to wg0 in case it exists
	if len(wgInterfaces) == 0 {
		wgInterfaces = []string{"wg0"}
	}

	// Combine with OpenVPN interface
	interfaces := append([]string{"tun0"}, wgInterfaces...)

	// Tear down VPN interfaces in parallel
	var wg sync.WaitGroup
	wg.Add(len(interfaces))
	for _, iface := range interfaces {
		go func(ifaceName string) {
			defer wg.Done()
			// For WireGuard, delete the interface entirely (it's a virtual interface)
			if strings.HasPrefix(ifaceName, "wg") {
				if _, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "delete", ifaceName); err != nil {
					m.logger.Debug("Failed to delete WireGuard interface", "interface", ifaceName, "error", err)
				}
			} else {
				// For tun/tap, just bring it down
				if _, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "set", ifaceName, "down"); err != nil {
					m.logger.Debug("Failed to bring down interface", "interface", ifaceName, "error", err)
				}
			}
		}(iface)
	}
	wg.Wait()

	// Remove the VPN endpoint route if we added one (no nested lock needed, already holding m.mu)
	endpointRoute := m.endpointRoute
	m.endpointRoute = ""
	if endpointRoute != "" {
		m.logger.Debug("Removing VPN endpoint route", "endpoint", endpointRoute)
		_, _ = m.executor.ExecuteWithTimeout(2*time.Second, "ip", "route", "del", endpointRoute)
	}

	// Restore default route via the physical interface
	m.restoreDefaultRoute()

	// Clear the active VPN state file
	m.clearActiveVPN()

	return nil
}

// restoreDefaultRoute finds the physical network interface and restores the default route
func (m *Manager) restoreDefaultRoute() {
	// Find the gateway from existing routes (VPN endpoint route points to original gateway)
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "route", "show")
	if err != nil {
		m.logger.Debug("Failed to get routes", "error", err)
		return
	}

	var gateway, iface string

	// Look for routes that have "via" - these point to the original gateway
	// Skip routes via VPN interfaces (wg*, tun*)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Look for "X.X.X.X via Y.Y.Y.Y dev ethX" pattern
		var routeGw, routeIface string
		for i, part := range parts {
			if part == "via" && i+1 < len(parts) {
				routeGw = parts[i+1]
			}
			if part == "dev" && i+1 < len(parts) {
				routeIface = parts[i+1]
			}
		}

		// Skip VPN interfaces
		if strings.HasPrefix(routeIface, "wg") || strings.HasPrefix(routeIface, "tun") {
			continue
		}

		// Found a route with gateway via physical interface
		if routeGw != "" && routeIface != "" {
			gateway = routeGw
			iface = routeIface
			break
		}
	}

	if gateway == "" || iface == "" {
		m.logger.Debug("Could not determine original gateway")
		return
	}

	// Restore default route
	m.logger.Debug("Restoring default route", "gateway", gateway, "interface", iface)
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "replace", "default", "via", gateway, "dev", iface)
	if err != nil {
		m.logger.Debug("Failed to restore default route", "error", err)
	}
}

// killProcess kills processes matching a pattern, with SIGKILL fallback if graceful shutdown fails
func (m *Manager) killProcess(pattern string) {
	// First try graceful shutdown (SIGTERM) with 1s timeout
	_, err := m.executor.ExecuteWithTimeout(1*time.Second, "pkill", "-f", pattern)
	if err != nil {
		m.logger.Debug("No process to kill or pkill failed", "pattern", pattern)
		return
	}

	// Wait briefly for graceful shutdown
	time.Sleep(200 * time.Millisecond)

	// Check if process is still running, if so force kill with SIGKILL
	_, err = m.executor.ExecuteWithTimeout(1*time.Second, "pgrep", "-f", pattern)
	if err == nil {
		// Process still running, force kill
		m.logger.Debug("Process still running, sending SIGKILL", "pattern", pattern)
		_, _ = m.executor.ExecuteWithTimeout(1*time.Second, "pkill", "-9", "-f", pattern)
	}
}

// ListVPNs lists available VPNs and their status
func (m *Manager) ListVPNs() ([]types.VPNStatus, error) {
	m.logger.Debug("Listing VPNs")

	// Read the active VPN name from state file (authoritative source)
	// Lock and read file directly to ensure consistent read with Connect/Disconnect
	m.mu.Lock()
	data, err := os.ReadFile(activeVPNFile)
	activeVPN := ""
	if err == nil {
		activeVPN = strings.TrimSpace(string(data))
	}
	m.mu.Unlock()

	// Track running VPN interfaces (used as fallback and for unnamed VPNs)
	runningOpenVPN := false
	runningWireGuard := make(map[string]bool) // interface name -> running

	// Check OpenVPN processes (with timeout)
	openvpnOutput, err := m.executor.ExecuteWithTimeout(2*time.Second, "pgrep", "-f", "openvpn")
	if err == nil && strings.TrimSpace(openvpnOutput) != "" {
		runningOpenVPN = true
	}

	// Check WireGuard interfaces (with timeout)
	wgOutput, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "show", "type", "wireguard")
	if err == nil && strings.TrimSpace(wgOutput) != "" {
		lines := strings.Split(wgOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "wg") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					iface := strings.Trim(parts[1], ":")
					runningWireGuard[iface] = true
				}
			}
		}
	}

	var vpns []types.VPNStatus

	// Get configured VPNs from config
	config := m.configMgr.GetConfig()
	if config != nil && config.VPN != nil {
		for name, vpnConfig := range config.VPN {
			status := types.VPNStatus{
				Name:      name,
				Type:      vpnConfig.Type,
				Connected: false,
				Interface: vpnConfig.Interface,
			}

			// Determine connection status:
			// 1. If we have an active VPN recorded, use that as authoritative
			// 2. Otherwise fall back to interface detection (for VPNs started outside net)
			if activeVPN != "" {
				// Use state file as authoritative source
				status.Connected = (name == activeVPN)
			} else {
				// Fall back to interface detection
				switch vpnConfig.Type {
				case "openvpn":
					status.Connected = runningOpenVPN
				case "wireguard":
					if vpnConfig.Interface != "" {
						status.Connected = runningWireGuard[vpnConfig.Interface]
					}
				}
			}

			if status.Interface == "" {
				switch vpnConfig.Type {
				case "openvpn":
					status.Interface = "tun0"
				case "wireguard":
					status.Interface = "wg0"
				}
			}

			vpns = append(vpns, status)
		}
	}

	// If no configured VPNs but we found running ones, add them as unnamed
	if len(vpns) == 0 {
		if runningOpenVPN {
			vpns = append(vpns, types.VPNStatus{
				Name:      "openvpn",
				Type:      "openvpn",
				Connected: true,
				Interface: "tun0",
			})
		}
		for iface := range runningWireGuard {
			vpns = append(vpns, types.VPNStatus{
				Name:      iface,
				Type:      "wireguard",
				Connected: true,
				Interface: iface,
			})
		}
	}

	return vpns, nil
}

// GenerateWireGuardKey generates a WireGuard key pair
func (m *Manager) GenerateWireGuardKey() (private, public string, err error) {
	m.logger.Info("Generating WireGuard key pair")

	// Generate private key
	var privateKey [32]byte
	_, err = rand.Read(privateKey[:])
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Derive public key using X25519 (non-deprecated API)
	publicKey, err := curve25519.X25519(privateKey[:], curve25519Basepoint[:])
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encode as base64
	private = base64.StdEncoding.EncodeToString(privateKey[:])
	public = base64.StdEncoding.EncodeToString(publicKey)

	m.logger.Info("Generated WireGuard key pair", "public_key", public)
	return private, public, nil
}

// removeFile removes a file, logging any error but not failing
func (m *Manager) removeFile(path string) {
	_, err := m.executor.ExecuteWithTimeout(1*time.Second, "rm", "-f", path)
	if err != nil {
		m.logger.Debug("Failed to remove temp file", "path", path, "error", err)
	}
}

// connectOpenVPN connects to an OpenVPN server
func (m *Manager) connectOpenVPN(config *types.VPNConfig) error {
	m.logger.Info("Connecting to OpenVPN")

	// Write config to temp file with secure permissions
	tempConfig := types.RuntimeDir + "/openvpn.conf"
	err := m.writeFile(tempConfig, config.Config)
	if err != nil {
		return fmt.Errorf("failed to write OpenVPN config: %w", err)
	}

	// Start OpenVPN (10s timeout for daemon startup)
	_, err = m.executor.ExecuteWithTimeout(10*time.Second, "openvpn", "--config", tempConfig, "--daemon")
	if err != nil {
		m.removeFile(tempConfig) // Clean up on failure
		return fmt.Errorf("failed to start OpenVPN: %w", err)
	}

	// Wait for tun interface to appear (up to 30s)
	m.logger.Debug("Waiting for OpenVPN tunnel to establish")
	for i := 0; i < 30; i++ {
		if _, err := m.executor.ExecuteWithTimeout(1*time.Second, "ip", "link", "show", "tun0"); err == nil {
			m.logger.Info("OpenVPN tunnel established")
			return nil
		}
		time.Sleep(time.Second)
	}
	// Clean up on failure
	m.killProcess("openvpn")
	m.removeFile(tempConfig)
	return fmt.Errorf("openvpn failed to establish tunnel within 30s")
}

// connectWireGuard connects to a WireGuard VPN
func (m *Manager) connectWireGuard(config *types.VPNConfig) error {
	m.logger.Info("Connecting to WireGuard VPN")

	// Default interface name if not specified
	iface := config.Interface
	if iface == "" {
		iface = "wg0"
	}

	// Write config to temp file with secure permissions
	tempConfig := types.RuntimeDir + "/wg.conf"
	err := m.writeFile(tempConfig, config.Config)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config: %w", err)
	}

	// Create WireGuard interface (ignore error if already exists)
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "add", "dev", iface, "type", "wireguard")
	if err != nil {
		m.logger.Warn("Failed to add WireGuard interface, it may already exist", "error", err)
	}

	// Set config
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "wg", "setconf", iface, tempConfig)
	// Clean up temp config file immediately after loading (contains credentials)
	m.removeFile(tempConfig)
	if err != nil {
		return fmt.Errorf("failed to set WireGuard config: %w", err)
	}

	// Set IP address if specified (use replace to handle existing addresses)
	if config.Address != "" {
		_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "addr", "replace", config.Address, "dev", iface)
		if err != nil {
			// Clean up interface on failure
			m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "del", iface)
			return fmt.Errorf("failed to set WireGuard IP: %w", err)
		}
	}

	// Bring interface up
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "link", "set", iface, "up")
	if err != nil {
		// Clean up interface on failure
		m.executor.ExecuteWithTimeout(2*time.Second, "ip", "link", "del", iface)
		return fmt.Errorf("failed to bring WireGuard interface up: %w", err)
	}

	// Add routes if gateway is enabled
	if config.Gateway {
		// Extract endpoint IP from config to route it via the original gateway
		endpoint := m.extractEndpoint(config.Config)
		if endpoint != "" {
			// Get current default gateway before we change it
			gateway, gwIface := m.getCurrentGateway()
			if gateway != "" && gwIface != "" {
				// Add route to VPN endpoint via original gateway
				m.logger.Debug("Adding route to VPN endpoint", "endpoint", endpoint, "gateway", gateway, "interface", gwIface)
				_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "replace", endpoint, "via", gateway, "dev", gwIface)
				if err != nil {
					m.logger.Warn("Failed to add route to VPN endpoint", "error", err)
				} else {
					// Store endpoint for cleanup on disconnect (already holding m.mu from Connect)
					m.endpointRoute = endpoint
				}
			}
		}

		// Set default route via WireGuard interface
		_, err = m.executor.ExecuteWithTimeout(5*time.Second, "ip", "route", "replace", "default", "dev", iface)
		if err != nil {
			m.logger.Warn("Failed to set default route", "error", err)
		}
	}

	m.logger.Info("WireGuard VPN connection established", "interface", iface)
	return nil
}

// extractEndpoint extracts the endpoint IP from a WireGuard config
func (m *Manager) extractEndpoint(config string) string {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "endpoint") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				endpoint := strings.TrimSpace(parts[1])
				// Remove port if present (e.g., "1.2.3.4:51820" -> "1.2.3.4")
				if idx := strings.LastIndex(endpoint, ":"); idx != -1 {
					endpoint = endpoint[:idx]
				}
				return endpoint
			}
		}
	}
	return ""
}

// getCurrentGateway returns the current default gateway IP and interface
func (m *Manager) getCurrentGateway() (gateway, iface string) {
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "ip", "route", "show", "default")
	if err != nil {
		return "", ""
	}
	// Parse "default via 10.10.120.1 dev wlp1s0"
	parts := strings.Fields(output)
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			gateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			iface = parts[i+1]
		}
	}
	return gateway, iface
}

// writeFile writes content to a file with secure permissions (0600)
// Uses install command to atomically create file with correct permissions
// avoiding TOCTOU race where file exists briefly with wrong permissions
func (m *Manager) writeFile(path, content string) error {
	// Use install -m 0600 /dev/stdin to atomically create file with correct permissions
	// This avoids the TOCTOU race of write-then-chmod
	_, err := m.executor.ExecuteWithInput("install", content, "-m", "0600", "/dev/stdin", path)
	return err
}

// setActiveVPN records the currently active VPN name to the state file
func (m *Manager) setActiveVPN(name string) error {
	// Ensure runtime directory exists
	if err := os.MkdirAll(filepath.Dir(activeVPNFile), 0755); err != nil {
		m.logger.Debug("Failed to create runtime directory", "error", err)
		// Non-fatal: status will fall back to interface detection
		return err
	}
	// Use 0600 for consistency with other runtime files (e.g., wg.conf, openvpn.conf)
	return os.WriteFile(activeVPNFile, []byte(name), 0600)
}

// clearActiveVPN removes the active VPN state file
func (m *Manager) clearActiveVPN() {
	if err := os.Remove(activeVPNFile); err != nil && !os.IsNotExist(err) {
		m.logger.Debug("Failed to remove active VPN file", "error", err)
	}
}

// getActiveVPN reads the currently active VPN name from the state file
func getActiveVPN() string {
	data, err := os.ReadFile(activeVPNFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
