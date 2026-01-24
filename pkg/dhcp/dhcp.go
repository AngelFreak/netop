package dhcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/angelfreak/net/pkg/types"
)

// dhcpManagerImpl implements the DHCPManager interface
type dhcpManagerImpl struct {
	executor       types.SystemExecutor
	logger         types.Logger
	dnsmasqPidFile string
	dnsmasqConfFile string
	currentConfig  *types.DHCPServerConfig
}

// NewDHCPManager creates a new DHCP server manager
func NewDHCPManager(executor types.SystemExecutor, logger types.Logger) types.DHCPManager {
	return &dhcpManagerImpl{
		executor:        executor,
		logger:          logger,
		dnsmasqPidFile:  types.RuntimeDir + "/dnsmasq-dhcp.pid",
		dnsmasqConfFile: types.RuntimeDir + "/dnsmasq-dhcp.conf",
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

	// Clean up configuration file
	os.Remove(d.dnsmasqConfFile)

	d.currentConfig = nil
	d.logger.Info("DHCP server stopped successfully")
	return nil
}

// IsRunning checks if the DHCP server is currently running
func (d *dhcpManagerImpl) IsRunning() bool {
	return d.dnsmasqRunning()
}

// validateConfig validates the DHCP server configuration
func (d *dhcpManagerImpl) validateConfig(config *types.DHCPServerConfig) error {
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	if config.Gateway == "" {
		return fmt.Errorf("gateway is required")
	}
	if config.IPRange == "" {
		return fmt.Errorf("IP range is required")
	}

	return nil
}

// generateDnsmasqConfig generates dnsmasq configuration file
func (d *dhcpManagerImpl) generateDnsmasqConfig(config *types.DHCPServerConfig) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("interface=%s\n", config.Interface))
	sb.WriteString(fmt.Sprintf("bind-interfaces\n"))

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

// dnsmasqRunning checks if dnsmasq is running
func (d *dhcpManagerImpl) dnsmasqRunning() bool {
	data, err := os.ReadFile(d.dnsmasqPidFile)
	if err != nil {
		return false
	}

	pid := strings.TrimSpace(string(data))
	processPath := filepath.Join("/proc", pid)

	if _, err := os.Stat(processPath); err != nil {
		return false
	}

	return true
}

// stopDnsmasq stops the dnsmasq process
func (d *dhcpManagerImpl) stopDnsmasq() error {
	data, err := os.ReadFile(d.dnsmasqPidFile)
	if err != nil {
		return fmt.Errorf("failed to read dnsmasq PID: %w", err)
	}

	pid := strings.TrimSpace(string(data))
	if _, err := d.executor.Execute("kill", pid); err != nil {
		return fmt.Errorf("failed to kill dnsmasq: %w", err)
	}

	os.Remove(d.dnsmasqPidFile)
	return nil
}
