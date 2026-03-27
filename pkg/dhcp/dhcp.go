package dhcp

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

// dhcpManagerImpl implements the DHCPManager interface
type dhcpManagerImpl struct {
	executor        types.SystemExecutor
	logger          types.Logger
	dnsmasqPidFile  string
	dnsmasqConfFile string
	leasesFile      string
	currentConfig   *types.DHCPServerConfig
}

// NewDHCPManager creates a new DHCP server manager
func NewDHCPManager(executor types.SystemExecutor, logger types.Logger) types.DHCPManager {
	return &dhcpManagerImpl{
		executor:        executor,
		logger:          logger,
		dnsmasqPidFile:  types.RuntimeDir + "/dnsmasq-dhcp.pid",
		dnsmasqConfFile: types.RuntimeDir + "/dnsmasq-dhcp.conf",
		leasesFile:      types.RuntimeDir + "/dnsmasq-dhcp.leases",
	}
}

// Start starts the DHCP server with the given configuration
func (d *dhcpManagerImpl) Start(config *types.DHCPServerConfig) error {
	d.logger.Info("Starting DHCP server", "interface", config.Interface, "range", config.IPRange)

	// Validate configuration
	if err := d.validateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Check if already running
	if d.IsRunning() {
		return fmt.Errorf("DHCP server is already running")
	}

	// Bring interface down
	if _, err := d.executor.Execute("ip", "link", "set", config.Interface, "down"); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Bring interface up
	if _, err := d.executor.Execute("ip", "link", "set", config.Interface, "up"); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Flush stale IP addresses (e.g., from a previous failed Stop)
	d.executor.Execute("ip", "addr", "flush", "dev", config.Interface)

	// Set IP address on interface with configurable netmask
	netmask := config.Netmask
	if netmask == "" {
		netmask = "24" // Default for backwards compatibility
	}
	if _, err := d.executor.Execute("ip", "addr", "add", config.Gateway+"/"+netmask, "dev", config.Interface); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// Generate dnsmasq configuration
	if err := d.generateDnsmasqConfig(config); err != nil {
		return fmt.Errorf("failed to generate dnsmasq config: %w", err)
	}

	// Start dnsmasq for DHCP
	d.logger.Debug("Starting dnsmasq")
	if _, err := d.executor.Execute("dnsmasq", "-C", d.dnsmasqConfFile, "-x", d.dnsmasqPidFile); err != nil {
		return fmt.Errorf("failed to start dnsmasq: %w", err)
	}

	d.currentConfig = config
	d.logger.Info("DHCP server started successfully", "interface", config.Interface)
	return nil
}

// Stop stops the running DHCP server
func (d *dhcpManagerImpl) Stop() error {
	d.logger.Info("Stopping DHCP server")

	if !d.IsRunning() {
		// Clean up stale PID/config files even if the process isn't running
		// (e.g., dnsmasq was killed externally)
		d.cleanupStaleFiles()
		return fmt.Errorf("DHCP server is not running")
	}

	// Stop dnsmasq
	if err := d.stopDnsmasq(); err != nil {
		return fmt.Errorf("failed to stop dnsmasq: %w", err)
	}

	// Clean up interface if we have config
	if d.currentConfig != nil {
		// Remove IP address
		if _, err := d.executor.Execute("ip", "addr", "flush", "dev", d.currentConfig.Interface); err != nil {
			d.logger.Warn("Failed to flush IP addresses", "error", err.Error())
		}

		// Bring interface down
		if _, err := d.executor.Execute("ip", "link", "set", d.currentConfig.Interface, "down"); err != nil {
			d.logger.Warn("Failed to bring interface down", "error", err.Error())
		}
	}

	// Clean up configuration and lease files
	os.Remove(d.dnsmasqConfFile)
	os.Remove(d.leasesFile)

	d.currentConfig = nil
	d.logger.Info("DHCP server stopped successfully")
	return nil
}

// IsRunning checks if the DHCP server is currently running
func (d *dhcpManagerImpl) IsRunning() bool {
	return d.dnsmasqRunning()
}

// GetCurrentConfig returns the current DHCP server configuration, or nil if not running
func (d *dhcpManagerImpl) GetCurrentConfig() *types.DHCPServerConfig {
	return d.currentConfig
}

// GetLeases reads and parses the dnsmasq lease file.
// Each line has format: expiry mac ip hostname clientid
func (d *dhcpManagerImpl) GetLeases() ([]types.DHCPLease, error) {
	data, err := os.ReadFile(d.leasesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read lease file: %w", err)
	}

	var leases []types.DHCPLease
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		expirySec, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}

		hostname := fields[3]
		if hostname == "*" {
			hostname = ""
		}

		leases = append(leases, types.DHCPLease{
			Expiry:   time.Unix(expirySec, 0),
			MAC:      fields[1],
			IP:       fields[2],
			Hostname: hostname,
		})
	}

	return leases, nil
}

// validateConfig validates the DHCP server configuration
func (d *dhcpManagerImpl) validateConfig(config *types.DHCPServerConfig) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	if strings.ContainsAny(config.Interface, " \t\n\r/") {
		return fmt.Errorf("invalid interface name: %q", config.Interface)
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

// generateDnsmasqConfig generates dnsmasq configuration file
func (d *dhcpManagerImpl) generateDnsmasqConfig(config *types.DHCPServerConfig) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("interface=%s\n", config.Interface))
	sb.WriteString("bind-interfaces\n")
	sb.WriteString(fmt.Sprintf("dhcp-leasefile=%s\n", d.leasesFile))

	// Set lease time
	leaseTime := config.LeaseTime
	if leaseTime == "" {
		leaseTime = "12h"
	}
	sb.WriteString(fmt.Sprintf("dhcp-range=%s,%s\n", config.IPRange, leaseTime))

	// Add DNS servers
	if len(config.DNS) > 0 {
		for _, dns := range config.DNS {
			sb.WriteString(fmt.Sprintf("server=%s\n", dns))
		}
	} else {
		// Default DNS servers
		sb.WriteString("server=8.8.8.8\n")
		sb.WriteString("server=8.8.4.4\n")
	}

	sb.WriteString(fmt.Sprintf("dhcp-option=3,%s\n", config.Gateway)) // Gateway

	// Set DNS servers for clients
	if len(config.DNS) > 0 {
		sb.WriteString(fmt.Sprintf("dhcp-option=6,%s\n", strings.Join(config.DNS, ",")))
	} else {
		sb.WriteString("dhcp-option=6,8.8.8.8,8.8.4.4\n")
	}

	if err := os.WriteFile(d.dnsmasqConfFile, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write dnsmasq config: %w", err)
	}

	return nil
}

// cleanupStaleFiles removes PID, config, and lease files left behind when
// dnsmasq was killed externally (e.g., by the OOM killer or manual kill).
func (d *dhcpManagerImpl) cleanupStaleFiles() {
	removed := false
	for _, f := range []string{d.dnsmasqPidFile, d.dnsmasqConfFile, d.leasesFile} {
		if err := os.Remove(f); err == nil {
			removed = true
		}
	}
	if removed {
		d.logger.Debug("Cleaned up stale DHCP server files")
	}
}

// dnsmasqRunning checks if dnsmasq is running by verifying PID and process name
func (d *dhcpManagerImpl) dnsmasqRunning() bool {
	data, err := os.ReadFile(d.dnsmasqPidFile)
	if err != nil {
		return false
	}

	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false
	}

	// Verify the process exists AND is dnsmasq (not a reused PID)
	comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(comm)) == "dnsmasq"
}

// stopDnsmasq stops the dnsmasq process
func (d *dhcpManagerImpl) stopDnsmasq() error {
	data, err := os.ReadFile(d.dnsmasqPidFile)
	if err != nil {
		return fmt.Errorf("failed to read dnsmasq PID: %w", err)
	}

	pid := strings.TrimSpace(string(data))
	// Validate PID is a positive integer before passing to kill
	if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
		os.Remove(d.dnsmasqPidFile)
		return fmt.Errorf("invalid PID in %s: %q", d.dnsmasqPidFile, pid)
	}
	if _, err := d.executor.Execute("kill", pid); err != nil {
		return fmt.Errorf("failed to kill dnsmasq: %w", err)
	}

	os.Remove(d.dnsmasqPidFile)
	return nil
}
