package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/angelfreak/net/pkg/types"
)

// App encapsulates all dependencies for testable CLI operations.
type App struct {
	Logger     types.Logger
	Executor   types.SystemExecutor
	ConfigMgr  types.ConfigManager
	WiFiMgr    types.WiFiManager
	VPNMgr     types.VPNManager
	NetworkMgr types.NetworkManager
	HotspotMgr types.HotspotManager
	DHCPMgr    types.DHCPManager

	Interface string
	NoVPN     bool
	Debug     bool

	Stdout io.Writer
	Stderr io.Writer
}

// printf writes formatted output to stdout
func (a *App) printf(format string, args ...interface{}) {
	fmt.Fprintf(a.Stdout, format, args...)
}

// println writes a line to stdout
func (a *App) println(args ...interface{}) {
	fmt.Fprintln(a.Stdout, args...)
}

// errorf writes formatted output to stderr
func (a *App) errorf(format string, args ...interface{}) {
	fmt.Fprintf(a.Stderr, format, args...)
}

// connectVPN connects to VPN if configured for the network
func (a *App) connectVPN(networkName string) {
	config := a.ConfigMgr.GetConfig()
	if config == nil {
		return
	}

	// Check if network has a specific VPN configured
	if netConfig, ok := config.Networks[networkName]; ok && netConfig.VPN != "" {
		a.Logger.Info("Connecting to network VPN", "vpn", netConfig.VPN)
		if err := a.VPNMgr.Connect(netConfig.VPN); err != nil {
			a.Logger.Error("Failed to connect to VPN", "error", err)
		} else {
			a.printf("✓ VPN connected (%s)\n", netConfig.VPN)
		}
		return
	}

	// Check if common VPN is configured
	if config.Common.VPN != "" {
		a.Logger.Info("Connecting to common VPN", "vpn", config.Common.VPN)
		if err := a.VPNMgr.Connect(config.Common.VPN); err != nil {
			a.Logger.Error("Failed to connect to VPN", "error", err)
		} else {
			a.printf("✓ VPN connected (%s)\n", config.Common.VPN)
		}
	}
}

// RunList lists active connections
func (a *App) RunList() error {
	connections, err := a.WiFiMgr.ListConnections()
	if err != nil {
		a.Logger.Error("Failed to list connections", "error", err)
		a.errorf("Error: %v\n", err)
		return err
	}

	if len(connections) == 0 {
		a.println("No active connections")
		return nil
	}

	for _, conn := range connections {
		a.printf("Interface: %s\n", conn.Interface)
		a.printf("SSID: %s\n", conn.SSID)
		a.printf("State: %s\n", conn.State)
		if conn.IP != nil {
			a.printf("IP: %s\n", conn.IP.String())
		}
		if conn.Gateway != nil {
			a.printf("Gateway: %s\n", conn.Gateway.String())
		}
		if len(conn.DNS) > 0 {
			a.printf("DNS: %v\n", conn.DNS)
		}
		a.println()
	}
	return nil
}

// RunScan scans for WiFi networks
func (a *App) RunScan(showOpen bool) error {
	networks, err := a.WiFiMgr.Scan()
	if err != nil {
		a.Logger.Error("Failed to scan networks", "error", err)
		a.errorf("Error: %v\n", err)
		return err
	}

	for _, network := range networks {
		if showOpen && network.Security != "Open" {
			continue
		}
		a.printf("%s (%s) - Signal: %d dBm - Security: %s\n",
			network.SSID, network.BSSID, network.Signal, network.Security)
	}
	return nil
}

// RunConnect connects to a network
func (a *App) RunConnect(name, password string) error {
	a.Logger.Debug("Connect command called", "name", name, "hasPassword", password != "")

	// Check if it's a configured network
	a.Logger.Debug("Looking up network config", "name", name)
	networkConfig, err := a.ConfigMgr.GetNetworkConfig(name)
	var connectedIface string
	if err != nil {
		// Not configured, treat as SSID
		a.Logger.Debug("Network config not found, treating as direct SSID", "name", name, "error", err)
		a.Logger.Info("Connecting to SSID", "ssid", name)
		err = a.WiFiMgr.Connect(name, password, "")
		if err != nil {
			a.Logger.Error("Failed to connect to WiFi", "error", err)
			return err
		}
		connectedIface = a.WiFiMgr.GetInterface()
	} else {
		// Use configured network - merge with common settings first
		networkConfig = a.ConfigMgr.MergeWithCommon(name, networkConfig)
		a.Logger.Debug("Found network config", "name", name, "ssid", networkConfig.SSID, "mac", networkConfig.MAC)
		a.Logger.Info("Connecting to configured network", "name", name)
		if password == "" {
			password = networkConfig.PSK
		}
		a.Logger.Debug("Using network config", "configSSID", networkConfig.SSID, "hasPSK", networkConfig.PSK != "")
		err = a.NetworkMgr.ConnectToConfiguredNetwork(networkConfig, password, a.WiFiMgr)
		if err != nil {
			a.Logger.Error("Failed to connect to configured network", "error", err)
			return err
		}
		if networkConfig.Interface != "" {
			connectedIface = networkConfig.Interface
		} else {
			connectedIface = a.WiFiMgr.GetInterface()
		}
	}

	// Display connection information
	a.printConnectionInfo(connectedIface)

	// Connect VPN if configured and not disabled
	if !a.NoVPN {
		a.connectVPN(name)
	}
	return nil
}

// printConnectionInfo displays connection details
func (a *App) printConnectionInfo(iface string) {
	connections, err := a.WiFiMgr.ListConnections()
	if err != nil {
		a.Logger.Debug("Failed to get connection info", "error", err)
		return
	}

	for _, conn := range connections {
		if conn.Interface == iface {
			a.println("Connected!")
			if conn.IP != nil {
				a.printf("  IP:      %s\n", conn.IP.String())
			}
			if conn.Gateway != nil {
				a.printf("  Gateway: %s\n", conn.Gateway.String())
			}
			if len(conn.DNS) > 0 {
				a.printf("  DNS:     %v\n", conn.DNS)
			}
			return
		}
	}
}

// RunStop stops network services
func (a *App) RunStop(interfaces []string) error {
	if len(interfaces) == 0 {
		// Stop all services
		a.Logger.Debug("Stopping all network services")

		var stoppedServices []string

		// Stop hotspot
		hotspotStatus, err := a.HotspotMgr.GetStatus()
		if err == nil && hotspotStatus.Running {
			a.Logger.Debug("Stopping hotspot")
			err = a.HotspotMgr.Stop()
			if err != nil {
				a.Logger.Error("Failed to stop hotspot", "error", err)
			} else {
				stoppedServices = append(stoppedServices, "Hotspot")
			}
		}

		// Stop DHCP server
		if a.DHCPMgr.IsRunning() {
			a.Logger.Debug("Stopping DHCP server")
			err = a.DHCPMgr.Stop()
			if err != nil {
				a.Logger.Error("Failed to stop DHCP server", "error", err)
			} else {
				stoppedServices = append(stoppedServices, "DHCP server")
			}
		}

		// Stop VPN
		a.Logger.Debug("Stopping VPN connections")
		err = a.VPNMgr.Disconnect("")
		if err != nil {
			a.Logger.Debug("No VPN to disconnect or failed", "error", err)
		} else {
			stoppedServices = append(stoppedServices, "VPN")
		}

		// Stop WiFi
		a.Logger.Debug("Stopping WiFi")
		err = a.WiFiMgr.Disconnect()
		if err != nil {
			a.Logger.Error("Failed to disconnect WiFi", "error", err)
		} else {
			stoppedServices = append(stoppedServices, "WiFi")
		}

		// Clear DNS configuration
		a.Logger.Debug("Clearing DNS configuration")
		err = a.NetworkMgr.ClearDNS()
		if err != nil {
			a.Logger.Debug("Failed to clear DNS", "error", err)
		} else {
			stoppedServices = append(stoppedServices, "DNS")
		}

		// Print summary
		if len(stoppedServices) > 0 {
			a.println("✓ Stopped services:")
			for _, service := range stoppedServices {
				a.printf("  • %s\n", service)
			}
		} else {
			a.println("No active services to stop")
		}
	} else {
		// Stop specific interfaces
		for _, iface := range interfaces {
			a.Logger.Debug("Stopping interface", "interface", iface)
			_, err := a.Executor.Execute("ip", "link", "set", iface, "down")
			if err != nil {
				a.Logger.Error("Failed to stop interface", "interface", iface, "error", err)
				a.printf("✗ Failed to stop %s\n", iface)
			} else {
				a.printf("✓ Stopped interface %s\n", iface)
			}
		}
	}
	return nil
}

// RunDNS sets DNS servers
func (a *App) RunDNS(servers []string) error {
	if len(servers) == 0 || (len(servers) == 1 && servers[0] == "dhcp") {
		err := a.NetworkMgr.DHCPRenew(a.Interface, "")
		if err != nil {
			a.Logger.Error("Failed to renew DHCP", "error", err)
			a.errorf("Error: %v\n", err)
			return err
		}
		a.println("✓ DNS restored via DHCP")
	} else {
		err := a.NetworkMgr.SetDNS(servers)
		if err != nil {
			a.Logger.Error("Failed to set DNS", "error", err)
			a.errorf("Error: %v\n", err)
			return err
		}
		a.printf("✓ DNS set to %s\n", strings.Join(servers, ", "))
	}
	return nil
}

// RunMAC sets MAC address
func (a *App) RunMAC(mac string) error {
	err := a.NetworkMgr.SetMAC(a.Interface, mac)
	if err != nil {
		a.Logger.Error("Failed to set MAC address", "error", err)
		a.errorf("Error: %v\n", err)
		return err
	}
	actualMAC, _ := a.NetworkMgr.GetMAC(a.Interface)
	if actualMAC != "" {
		a.printf("✓ MAC address set to %s\n", actualMAC)
	} else {
		a.println("✓ MAC address changed")
	}
	return nil
}

// RunVPN manages VPN connections
func (a *App) RunVPN(arg string) error {
	if arg == "" {
		// List VPNs
		vpns, err := a.VPNMgr.ListVPNs()
		if err != nil {
			a.Logger.Error("Failed to list VPNs", "error", err)
			return err
		}

		if len(vpns) == 0 {
			a.println("No active VPNs")
			return nil
		}

		for _, v := range vpns {
			status := "disconnected"
			if v.Connected {
				status = "connected"
			}
			a.printf("%s (%s) - %s\n", v.Name, v.Type, status)
		}
		return nil
	}

	if arg == "stop" {
		err := a.VPNMgr.Disconnect("")
		if err != nil {
			a.Logger.Error("Failed to disconnect VPNs", "error", err)
			return err
		}
		a.println("✓ VPN disconnected")
	} else {
		err := a.VPNMgr.Connect(arg)
		if err != nil {
			a.Logger.Error("Failed to connect to VPN", "name", arg, "error", err)
			return err
		}
		a.printf("✓ VPN connected (%s)\n", arg)
	}
	return nil
}

// RunGenkey generates a WireGuard key pair
func (a *App) RunGenkey() error {
	private, public, err := a.VPNMgr.GenerateWireGuardKey()
	if err != nil {
		a.Logger.Error("Failed to generate WireGuard key", "error", err)
		a.errorf("Error: %v\n", err)
		return err
	}

	a.println("✓ WireGuard keys generated")
	a.printf("Private key: %s\n", private)
	a.printf("Public key: %s\n", public)
	return nil
}

// RunShow displays configuration
func (a *App) RunShow(networkName string) error {
	if networkName == "" {
		// Show all configurations
		config := a.ConfigMgr.GetConfig()
		if config == nil {
			a.println("No configuration loaded")
			return nil
		}

		a.println("Common Configuration:")
		if config.Common.DNS != nil {
			a.printf("  DNS: %v\n", config.Common.DNS)
		}
		if config.Common.MAC != "" {
			a.printf("  MAC: %s\n", config.Common.MAC)
		}
		if config.Common.Hostname != "" {
			a.printf("  Hostname: %s\n", config.Common.Hostname)
		}
		if config.Common.VPN != "" {
			a.printf("  VPN: %s\n", config.Common.VPN)
		}

		a.println("\nNetworks:")
		for name, netConfig := range config.Networks {
			a.printf("  %s:\n", name)
			if netConfig.Interface != "" {
				a.printf("    Interface: %s\n", netConfig.Interface)
			}
			if netConfig.SSID != "" {
				a.printf("    SSID: %s\n", netConfig.SSID)
			}
			if netConfig.VPN != "" {
				a.printf("    VPN: %s\n", netConfig.VPN)
			}
		}

		a.println("\nVPNs:")
		for name, vpnConfig := range config.VPN {
			a.printf("  %s: %s\n", name, vpnConfig.Type)
		}

		a.println("\nIgnored Interfaces:")
		for _, iface := range config.Ignored.Interfaces {
			a.printf("  %s\n", iface)
		}
	} else {
		// Show specific network
		config, err := a.ConfigMgr.GetNetworkConfig(networkName)
		if err != nil {
			a.Logger.Error("Failed to get network config", "name", networkName, "error", err)
			a.errorf("Error: %v\n", err)
			return err
		}

		merged := a.ConfigMgr.MergeWithCommon(networkName, config)

		a.printf("Network: %s\n", networkName)
		if merged.Interface != "" {
			a.printf("Interface: %s\n", merged.Interface)
		}
		if merged.SSID != "" {
			a.printf("SSID: %s\n", merged.SSID)
		}
		if len(merged.DNS) > 0 {
			a.printf("DNS: %s\n", strings.Join(merged.DNS, ", "))
		}
		if merged.MAC != "" {
			a.printf("MAC: %s\n", merged.MAC)
		}
		if merged.Hostname != "" {
			a.printf("Hostname: %s\n", merged.Hostname)
		}
		if merged.VPN != "" {
			a.printf("VPN: %s\n", merged.VPN)
		}
	}
	return nil
}

// RunStatus displays full network status
func (a *App) RunStatus() error {
	a.println("Network Status")
	a.println("==============")

	// Get current connection info
	connections, err := a.WiFiMgr.ListConnections()
	if err != nil {
		a.Logger.Debug("Failed to get connection info", "error", err)
	}

	// Get hostname
	hostname, err := a.Executor.Execute("hostname")
	if err != nil {
		a.Logger.Debug("Failed to get hostname", "error", err)
	} else {
		a.printf("\nHostname:  %s\n", strings.TrimSpace(hostname))
	}

	// Interface info
	a.printf("Interface: %s\n", a.Interface)

	// Get current MAC address
	mac, err := a.NetworkMgr.GetMAC(a.Interface)
	if err != nil {
		a.Logger.Debug("Failed to get MAC address", "error", err)
	} else {
		macInfo := mac
		config := a.ConfigMgr.GetConfig()
		if config != nil {
			commonMAC := config.Common.MAC
			if commonMAC == "" || commonMAC == "random" {
				macInfo = mac + " (random)"
			} else if commonMAC == "default" {
				macInfo = mac + " (randomized Apple OUI)"
			} else if strings.Contains(commonMAC, "??") {
				macInfo = mac + " (randomized from " + commonMAC + ")"
			}
		}
		a.printf("MAC:       %s\n", macInfo)
	}

	if len(connections) > 0 {
		conn := connections[0]

		if conn.SSID != "" {
			a.printf("SSID:      %s\n", conn.SSID)
		}

		a.printf("State:     %s\n", conn.State)

		if conn.IP != nil {
			a.printf("IP:        %s\n", conn.IP.String())
		} else {
			a.printf("IP:        (none)\n")
		}

		if conn.Gateway != nil {
			a.printf("Gateway:   %s\n", conn.Gateway.String())
		}

		if len(conn.DNS) > 0 {
			a.printf("DNS:       ")
			for i, dns := range conn.DNS {
				if i > 0 {
					a.printf(", ")
				}
				a.printf("%s", dns.String())
			}
			a.println()
		}
	} else {
		a.println("State:     disconnected")
	}

	// VPN status
	a.println("\nVPN")
	a.println("---")
	vpns, err := a.VPNMgr.ListVPNs()
	if err != nil {
		a.Logger.Debug("Failed to list VPNs", "error", err)
		a.println("(unable to query VPN status)")
	} else if len(vpns) == 0 {
		a.println("(none active)")
	} else {
		for _, v := range vpns {
			status := "disconnected"
			if v.Connected {
				status = "connected"
			}
			a.printf("%s (%s): %s\n", v.Name, v.Type, status)
			if v.Interface != "" {
				a.printf("  Interface: %s\n", v.Interface)
			}
		}
	}

	// Hotspot status
	a.println("\nHotspot")
	a.println("-------")
	hotspotStatus, err := a.HotspotMgr.GetStatus()
	if err != nil {
		a.Logger.Debug("Failed to get hotspot status", "error", err)
		a.println("(unable to query hotspot status)")
	} else if !hotspotStatus.Running {
		a.println("(not running)")
	} else {
		a.printf("SSID:      %s\n", hotspotStatus.SSID)
		a.printf("Interface: %s\n", hotspotStatus.Interface)
		if hotspotStatus.Gateway != nil {
			a.printf("Gateway:   %s\n", hotspotStatus.Gateway.String())
		}
		a.printf("Clients:   %d\n", hotspotStatus.Clients)
	}

	// DHCP server status
	a.println("\nDHCP Server")
	a.println("-----------")
	if a.DHCPMgr.IsRunning() {
		a.println("running")
	} else {
		a.println("(not running)")
	}

	return nil
}

// RunHotspot manages the WiFi hotspot
func (a *App) RunHotspot(action string, config *types.HotspotConfig) error {
	switch action {
	case "start":
		if config == nil {
			a.errorf("Configuration required for start action\n")
			return fmt.Errorf("configuration required")
		}
		err := a.HotspotMgr.Start(config)
		if err != nil {
			a.Logger.Error("Failed to start hotspot", "error", err)
			a.printf("Failed to start hotspot: %v\n", err)
			return err
		}
		a.printf("✓ Hotspot started successfully\n")
		a.printf("  SSID:     %s\n", config.SSID)
		if config.Password != "" {
			a.printf("  Password: %s\n", config.Password)
		} else {
			a.printf("  Security: Open\n")
		}
		a.printf("  Gateway:  %s\n", config.Gateway)

	case "stop":
		err := a.HotspotMgr.Stop()
		if err != nil {
			a.Logger.Error("Failed to stop hotspot", "error", err)
			a.printf("Failed to stop hotspot: %v\n", err)
			return err
		}
		a.println("✓ Hotspot stopped successfully")

	case "status":
		status, err := a.HotspotMgr.GetStatus()
		if err != nil {
			a.Logger.Error("Failed to get hotspot status", "error", err)
			return err
		}

		if !status.Running {
			a.println("Hotspot is not running")
			return nil
		}

		a.println("Hotspot Status:")
		a.printf("  SSID:      %s\n", status.SSID)
		a.printf("  Interface: %s\n", status.Interface)
		if status.Gateway != nil {
			a.printf("  Gateway:   %s\n", status.Gateway.String())
		}
		a.printf("  Clients:   %d\n", status.Clients)

	default:
		a.printf("Unknown action: %s\n", action)
		return fmt.Errorf("unknown action: %s", action)
	}
	return nil
}

// RunDHCPServer manages the DHCP server
func (a *App) RunDHCPServer(action string, config *types.DHCPServerConfig) error {
	switch action {
	case "start":
		if config == nil {
			a.errorf("Configuration required for start action\n")
			return fmt.Errorf("configuration required")
		}
		err := a.DHCPMgr.Start(config)
		if err != nil {
			a.Logger.Error("Failed to start DHCP server", "error", err)
			a.printf("Failed to start DHCP server: %v\n", err)
			return err
		}
		a.printf("✓ DHCP server started successfully\n")
		a.printf("  Interface: %s\n", config.Interface)
		a.printf("  Gateway:   %s\n", config.Gateway)
		a.printf("  IP Range:  %s\n", config.IPRange)
		a.printf("  Lease:     %s\n", config.LeaseTime)

	case "stop":
		err := a.DHCPMgr.Stop()
		if err != nil {
			a.Logger.Error("Failed to stop DHCP server", "error", err)
			a.printf("Failed to stop DHCP server: %v\n", err)
			return err
		}
		a.println("✓ DHCP server stopped successfully")

	case "status":
		if a.DHCPMgr.IsRunning() {
			a.println("DHCP server is running")
		} else {
			a.println("DHCP server is not running")
		}

	default:
		a.printf("Unknown action: %s\n", action)
		return fmt.Errorf("unknown action: %s", action)
	}
	return nil
}
