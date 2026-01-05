package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/angelfreak/net/pkg/config"
	"github.com/angelfreak/net/pkg/dhcp"
	"github.com/angelfreak/net/pkg/dhcpclient"
	"github.com/angelfreak/net/pkg/hotspot"
	"github.com/angelfreak/net/pkg/network"
	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
	"github.com/angelfreak/net/pkg/vpn"
	"github.com/angelfreak/net/pkg/wifi"
	"github.com/spf13/cobra"
)

var (
	configPath string
	iface      string
	noVPN      bool
	debug      bool

	cfgManager  types.ConfigManager
	sysExecutor types.SystemExecutor
	logger      types.Logger
	wifiMgr     types.WiFiManager
	vpnMgr      types.VPNManager
	netMgr      types.NetworkManager
	hotspotMgr  types.HotspotManager
	dhcpMgr     types.DHCPManager
)

// ensureRoot re-executes the program with sudo if not running as root.
func ensureRoot() {
	if os.Geteuid() == 0 {
		return // Already root
	}

	// Skip sudo for commands that don't need root
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "help" ||
			arg == "completion" || arg == "--version" || arg == "-v" ||
			arg == "status" || arg == "show" || arg == "list" {
			return
		}
	}

	// Get the executable path
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	// Build the command: sudo <executable> <args...>
	args := append([]string{executable}, os.Args[1:]...)

	// Use syscall.Exec to replace the current process with sudo
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: sudo not found: %v\n", err)
		os.Exit(1)
	}

	// Replace current process with sudo
	err = syscall.Exec(sudoPath, append([]string{"sudo"}, args...), os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to execute sudo: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	// Ensure we're running as root for network operations
	ensureRoot()

	// Ensure runtime directory exists with secure permissions
	if err := os.MkdirAll(types.RuntimeDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to create runtime directory %s: %v\n", types.RuntimeDir, err)
		fmt.Fprintf(os.Stderr, "Hint: try running with sudo\n")
	}

	var rootCmd = &cobra.Command{
		Use:   "net [network-name]",
		Short: "Super lightweight network manager",
		Long: `A lightweight network manager for WiFi, VPN, and network configuration.

Quick Start:
  net                     Show current connections
  net <name>              Connect to a configured network
  net connect <ssid>      Connect to any WiFi network
  net scan                Scan for available networks
  net stop                Disconnect everything

Examples:
  net home                Connect to network "home" from config
  net connect CoffeeShop  Connect to WiFi "CoffeeShop"
  net scan open           Show only open (unprotected) networks
  net vpn work            Connect to VPN "work"
  net dns 1.1.1.1 8.8.8.8 Set custom DNS servers
  net mac random          Randomize MAC address
  net status              Show full network status`,
		// Allow unknown args so that "net damon" works (handled in Run function)
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		Args:               cobra.ArbitraryArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return getNetworkNames(), cobra.ShellCompDirectiveNoFileComp
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initializeManagers()
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Default behavior: if no args, run list; if one arg, run connect
			if len(args) == 0 {
				listCmd.Run(cmd, args)
			} else if len(args) == 1 {
				connectCmd.Run(cmd, append(args, ""))
			} else {
				cmd.Help()
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Select configuration file")
	rootCmd.PersistentFlags().StringVar(&iface, "iface", "", "Select networking interface")
	rootCmd.PersistentFlags().BoolVar(&noVPN, "no-vpn", false, "Don't connect to VPN")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")

	// Commands
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(macCmd)
	rootCmd.AddCommand(vpnCmd)
	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(hotspotCmd)
	rootCmd.AddCommand(dhcpServerCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(completionCmd)

	// Add --install flag to completion command
	completionCmd.Flags().Bool("install", false, "Install completion script to system location")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initializeManagers() {
	// Initialize logger
	logger = system.NewLogger(debug)

	// Initialize system executor
	sysExecutor = system.NewExecutor(logger, debug)

	// Initialize config manager
	cfgManager = config.NewManager(logger)

	// Load config
	config, err := cfgManager.LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load config", "error", err)
	} else {
		logger.Debug("Config loaded", "networks", len(config.Networks))
	}

	// Determine interface
	if iface == "" {
		iface = findDefaultInterface()
	}

	// Initialize DHCP client manager (used by wifi and network managers)
	dhcpClientMgr := dhcpclient.NewManager(sysExecutor, logger)

	// Initialize managers
	wifiMgr = wifi.NewManager(sysExecutor, logger, iface, dhcpClientMgr)
	vpnMgr = vpn.NewManager(sysExecutor, logger, cfgManager)
	netMgr = network.NewManager(sysExecutor, logger, dhcpClientMgr)
	hotspotMgr = hotspot.NewHotspotManager(sysExecutor, logger)
	dhcpMgr = dhcp.NewDHCPManager(sysExecutor, logger)
}

// createApp creates an App instance from the global managers for testable execution.
func createApp() *App {
	return &App{
		Logger:     logger,
		Executor:   sysExecutor,
		ConfigMgr:  cfgManager,
		WiFiMgr:    wifiMgr,
		VPNMgr:     vpnMgr,
		NetworkMgr: netMgr,
		HotspotMgr: hotspotMgr,
		DHCPMgr:    dhcpMgr,
		Interface:  iface,
		NoVPN:      noVPN,
		Debug:      debug,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
}

func findDefaultInterface() string {
	// Try to find first wireless interface
	output, err := sysExecutor.Execute("iw", "dev")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Interface ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					logger.Debug("Found wireless interface", "interface", parts[1])
					return parts[1]
				}
			}
		}
	}

	// Fallback to wlan0
	logger.Debug("No wireless interface found, using fallback", "interface", "wlan0")
	return "wlan0"
}

// Command definitions

// getNetworkNames returns a list of all network names from the config for completion
func getNetworkNames() []string {
	// Determine config file path
	configFile := configPath
	if configFile == "" {
		// Use default path
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		// Handle SUDO_USER for sudo execution
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			home = "/home/" + sudoUser
		}
		configFile = home + "/.net/config.yaml"
	}

	// Read the config file to get all top-level keys
	file, err := os.ReadFile(configFile)
	if err != nil {
		return nil
	}

	var networks []string
	allKeys := make(map[string]bool)

	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check if this is a top-level key (no leading whitespace in original line)
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.Contains(line, ":") {
			key := strings.TrimSpace(strings.Split(line, ":")[0])
			// Skip special sections
			if key != "common" && key != "ignored" && key != "vpn" {
				allKeys[key] = true
			}
		}
	}

	for key := range allKeys {
		networks = append(networks, key)
	}

	return networks
}

// printConnectionInfo displays the current connection information for the given interface
func printConnectionInfo(iface string) {
	conn, err := netMgr.GetConnectionInfo(iface)
	if err != nil {
		logger.Warn("Failed to retrieve connection info", "error", err)
		return
	}

	// Print connection success message with details
	fmt.Println("✓ Connected successfully")

	if conn.SSID != "" {
		fmt.Printf("  SSID:     %s\n", conn.SSID)
	}

	if conn.IP != nil {
		fmt.Printf("  IP:       %s\n", conn.IP.String())
	}

	if conn.Gateway != nil {
		fmt.Printf("  Gateway:  %s\n", conn.Gateway.String())
	}

	if len(conn.DNS) > 0 {
		fmt.Printf("  DNS:      ")
		for i, dns := range conn.DNS {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", dns.String())
		}
		fmt.Println()
	}

	fmt.Println()
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List active connections with IP, gateway, and DNS info",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunList(); err != nil {
			os.Exit(1)
		}
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [open]",
	Short: "Scan for WiFi networks (use 'scan open' to show only unprotected)",
	Run: func(cmd *cobra.Command, args []string) {
		showOpen := len(args) > 0 && args[0] == "open"
		if err := createApp().RunScan(showOpen); err != nil {
			os.Exit(1)
		}
	},
}

var connectCmd = &cobra.Command{
	Use:   "connect <name|ssid> [password]",
	Short: "Connect to a configured network or WiFi SSID",
	Long: `Connect to a network by config name or WiFi SSID.

If <name> matches a network in ~/.net/config.yaml, uses that config.
Otherwise, treats it as a WiFi SSID and connects directly.

Examples:
  net connect home              Use "home" from config
  net connect CoffeeShop        Connect to SSID "CoffeeShop" (open)
  net connect CoffeeShop pass   Connect with password`,
	Args: cobra.RangeArgs(1, 2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getNetworkNames(), cobra.ShellCompDirectiveNoFileComp
	},
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		password := ""
		if len(args) > 1 {
			password = args[1]
		}
		if err := createApp().RunConnect(name, password); err != nil {
			os.Exit(1)
		}
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop [interface...]",
	Short: "Disconnect everything (WiFi, VPN, hotspot, DHCP) or specific interfaces",
	Long: `Stop all network services or bring down specific interfaces.

Without arguments: Stops WiFi, VPN, hotspot, DHCP server, and clears DNS.
With arguments: Brings down only the specified interfaces.

Examples:
  net stop              Disconnect everything
  net stop wlan0        Bring down wlan0 only
  net stop eth0 wlan0   Bring down multiple interfaces`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunStop(args); err != nil {
			os.Exit(1)
		}
	},
}

var dnsCmd = &cobra.Command{
	Use:   "dns [server...]",
	Short: "Set DNS servers (or 'dns dhcp' to restore DHCP DNS)",
	Long: `Set custom DNS servers or restore DHCP-provided DNS.

Examples:
  net dns 1.1.1.1              Use Cloudflare DNS
  net dns 8.8.8.8 8.8.4.4      Use Google DNS
  net dns 1.1.1.1 9.9.9.9      Cloudflare + Quad9
  net dns dhcp                 Restore DHCP-provided DNS`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunDNS(args); err != nil {
			os.Exit(1)
		}
	},
}

var macCmd = &cobra.Command{
	Use:   "mac [address]",
	Short: "Set MAC address (random, or specific like AA:BB:CC:DD:EE:FF)",
	Long: `Change the MAC address of the network interface.

Without arguments: Generates a random MAC address.
With argument: Sets the specified MAC address.

Examples:
  net mac                         Random MAC
  net mac random                  Random MAC (explicit)
  net mac AA:BB:CC:DD:EE:FF       Set specific MAC
  net mac default                 Randomize with Apple OUI prefix`,
	Run: func(cmd *cobra.Command, args []string) {
		mac := ""
		if len(args) > 0 {
			mac = args[0]
		}
		if err := createApp().RunMAC(mac); err != nil {
			os.Exit(1)
		}
	},
}

var vpnCmd = &cobra.Command{
	Use:   "vpn [name|stop]",
	Short: "List VPNs, connect, or disconnect",
	Long: `Manage VPN connections (OpenVPN and WireGuard).

Without arguments: Lists all configured VPNs and their status.
With name: Connects to the specified VPN from config.
With "stop": Disconnects all VPNs.

Examples:
  net vpn                 List all VPNs (configured and running)
  net vpn work            Connect to VPN "work"
  net vpn stop            Disconnect all VPNs`,
	Run: func(cmd *cobra.Command, args []string) {
		arg := ""
		if len(args) > 0 {
			arg = args[0]
		}
		if err := createApp().RunVPN(arg); err != nil {
			os.Exit(1)
		}
	},
}

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a WireGuard private/public key pair",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunGenkey(); err != nil {
			os.Exit(1)
		}
	},
}

var showCmd = &cobra.Command{
	Use:   "show [network]",
	Short: "Show config file settings (all networks or specific one)",
	Long: `Display configuration from ~/.net/config.yaml.

Without arguments: Shows common settings, all networks, VPNs, and ignored interfaces.
With network name: Shows detailed config for that specific network.

Examples:
  net show                Show all configuration
  net show home           Show config for network "home"`,
	Run: func(cmd *cobra.Command, args []string) {
		networkName := ""
		if len(args) > 0 {
			networkName = args[0]
		}
		if err := createApp().RunShow(networkName); err != nil {
			os.Exit(1)
		}
	},
}

var hotspotCmd = &cobra.Command{
	Use:   "hotspot [start|stop|status]",
	Short: "Create a WiFi hotspot to share your connection",
	Long: `Create and manage a WiFi access point.

Without arguments: Shows hotspot status.

Features:
  - Supports 2.4GHz (channels 1-14) and 5GHz (channels 36-165)
  - Automatic NAT/IP forwarding for internet sharing
  - WPA2 encryption with password protection

Examples:
  net hotspot                           Show status
  net hotspot start                     Start with defaults (SSID: net-hotspot)
  net hotspot start --ssid MyHotspot    Start with custom SSID
  net hotspot start --password secret   Start with WPA2 password
  net hotspot start --channel 36        Start on 5GHz channel 36
  net hotspot stop                      Stop the hotspot`,
	Run: func(cmd *cobra.Command, args []string) {
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}

		var config *types.HotspotConfig
		if action == "start" {
			// Get configuration from flags or use defaults
			ssid, _ := cmd.Flags().GetString("ssid")
			password, _ := cmd.Flags().GetString("password")
			channel, _ := cmd.Flags().GetInt("channel")
			gateway, _ := cmd.Flags().GetString("gateway")
			ipRange, _ := cmd.Flags().GetString("ip-range")
			dnsServers, _ := cmd.Flags().GetStringSlice("dns")

			// Set defaults if not provided
			if ssid == "" {
				ssid = "net-hotspot"
			}
			if channel == 0 {
				channel = 6
			}
			if gateway == "" {
				gateway = "192.168.50.1"
			}
			if ipRange == "" {
				ipRange = "192.168.50.50,192.168.50.150"
			}
			if len(dnsServers) == 0 {
				dnsServers = []string{"8.8.8.8", "8.8.4.4"}
			}

			config = &types.HotspotConfig{
				Interface: iface,
				SSID:      ssid,
				Password:  password,
				Channel:   channel,
				Gateway:   gateway,
				IPRange:   ipRange,
				DNS:       dnsServers,
			}
		}

		if err := createApp().RunHotspot(action, config); err != nil {
			os.Exit(1)
		}
	},
}

func init() {
	hotspotCmd.Flags().String("ssid", "", "Hotspot SSID (default: net-hotspot)")
	hotspotCmd.Flags().String("password", "", "Hotspot password (min 8 chars, empty for open network)")
	hotspotCmd.Flags().Int("channel", 6, "WiFi channel (2.4GHz: 1-14, 5GHz: 36,40,44,48,149,153,157,161,165)")
	hotspotCmd.Flags().String("gateway", "192.168.50.1", "Gateway IP address")
	hotspotCmd.Flags().String("ip-range", "192.168.50.50,192.168.50.150", "DHCP IP range")
	hotspotCmd.Flags().StringSlice("dns", []string{"8.8.8.8", "8.8.4.4"}, "DNS servers")

	dhcpServerCmd.Flags().String("gateway", "192.168.100.1", "Gateway IP address")
	dhcpServerCmd.Flags().String("ip-range", "192.168.100.50,192.168.100.150", "DHCP IP range")
	dhcpServerCmd.Flags().StringSlice("dns", []string{"8.8.8.8", "8.8.4.4"}, "DNS servers")
	dhcpServerCmd.Flags().String("lease-time", "12h", "DHCP lease time (e.g., 12h, 24h)")
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show full network status (connection, VPN, hotspot, DHCP)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := createApp().RunStatus(); err != nil {
			os.Exit(1)
		}
	},
}

var dhcpServerCmd = &cobra.Command{
	Use:   "dhcp [start|stop|status]",
	Short: "Run a DHCP server (useful for sharing connection via ethernet)",
	Long: `Start a DHCP server to assign IP addresses to connected devices.

Useful when sharing your connection via ethernet cable.

Examples:
  net dhcp                              Show status
  net dhcp start                        Start with defaults
  net dhcp start --gateway 10.0.0.1     Custom gateway
  net dhcp stop                         Stop the server`,
	Run: func(cmd *cobra.Command, args []string) {
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}

		var config *types.DHCPServerConfig
		if action == "start" {
			// Get configuration from flags or use defaults
			gateway, _ := cmd.Flags().GetString("gateway")
			ipRange, _ := cmd.Flags().GetString("ip-range")
			dnsServers, _ := cmd.Flags().GetStringSlice("dns")
			leaseTime, _ := cmd.Flags().GetString("lease-time")

			// Set defaults if not provided
			if gateway == "" {
				gateway = "192.168.100.1"
			}
			if ipRange == "" {
				ipRange = "192.168.100.50,192.168.100.150"
			}
			if len(dnsServers) == 0 {
				dnsServers = []string{"8.8.8.8", "8.8.4.4"}
			}
			if leaseTime == "" {
				leaseTime = "12h"
			}

			config = &types.DHCPServerConfig{
				Interface: iface,
				Gateway:   gateway,
				IPRange:   ipRange,
				DNS:       dnsServers,
				LeaseTime: leaseTime,
			}
		}

		if err := createApp().RunDHCPServer(action, config); err != nil {
			os.Exit(1)
		}
	},
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script for your shell",
	Long: `Generate completion script for your shell.

By default, this command outputs the completion script to stdout.
Use the output in your shell configuration or install it to the system location.

Examples:

  # Load bash completion in current session
  $ source <(net completion bash)

  # Install bash completion for all sessions
  $ sudo net completion bash --install

  # Add to your bashrc to load on every shell startup
  $ echo 'source <(net completion bash)' >> ~/.bashrc

  # Install zsh completion
  $ sudo net completion zsh --install

  # Install fish completion
  $ sudo net completion fish --install

After installation, restart your shell to enable tab completion for 'net' commands.

`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		shell := args[0]
		install, _ := cmd.Flags().GetBool("install")

		if install {
			// Install completion script to system location
			installCompletion(shell, cmd)
			return
		}

		// Default behavior: print to stdout
		switch shell {
		case "bash":
			cmd.Root().GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			cmd.Root().GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
		}
	},
}

// Helper functions

func connectVPN(networkName string) {
	// Get network config to find VPN
	config, err := cfgManager.GetNetworkConfig(networkName)
	if err != nil {
		logger.Debug("No network config found for VPN check", "network", networkName)
		return
	}

	// Merge with common settings to get default VPN if not specified
	merged := cfgManager.MergeWithCommon(networkName, config)

	if merged.VPN == "" {
		logger.Debug("No VPN configured for network", "network", networkName)
		return
	}

	logger.Info("Connecting to VPN", "vpn", merged.VPN)
	err = vpnMgr.Connect(merged.VPN)
	if err != nil {
		logger.Error("Failed to connect to VPN", "vpn", merged.VPN, "error", err)
		fmt.Fprintf(os.Stderr, "✗ VPN connection failed (%s): %v\n", merged.VPN, err)
	} else {
		fmt.Printf("✓ VPN connected (%s)\n", merged.VPN)
	}
}

// installCompletion installs the completion script to the appropriate system location
func installCompletion(shell string, cmd *cobra.Command) {
	var installPath string
	var content strings.Builder

	// Generate completion script
	switch shell {
	case "bash":
		cmd.Root().GenBashCompletion(&content)
		// Check common bash completion directories
		if _, err := os.Stat("/etc/bash_completion.d"); err == nil {
			installPath = "/etc/bash_completion.d/net"
		} else if _, err := os.Stat("/usr/local/etc/bash_completion.d"); err == nil {
			installPath = "/usr/local/etc/bash_completion.d/net"
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: No bash completion directory found.\n")
			fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: net completion bash > /path/to/completion/dir/net\n")
			return
		}
	case "zsh":
		cmd.Root().GenZshCompletion(&content)
		// Try to find zsh completion directory
		homeDir, _ := os.UserHomeDir()
		installPath = homeDir + "/.local/share/zsh/site-functions/_net"
		// Create directory if it doesn't exist
		os.MkdirAll(homeDir+"/.local/share/zsh/site-functions", 0755)
	case "fish":
		cmd.Root().GenFishCompletion(&content, true)
		homeDir, _ := os.UserHomeDir()
		installPath = homeDir + "/.config/fish/completions/net.fish"
		// Create directory if it doesn't exist
		os.MkdirAll(homeDir+"/.config/fish/completions", 0755)
	case "powershell":
		fmt.Fprintf(cmd.ErrOrStderr(), "PowerShell completion installation not supported.\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: net completion powershell > net.ps1\n")
		return
	default:
		fmt.Fprintf(cmd.ErrOrStderr(), "Unsupported shell: %s\n", shell)
		return
	}

	// Check if we need sudo for system directories
	needsSudo := strings.HasPrefix(installPath, "/etc/") || strings.HasPrefix(installPath, "/usr/")

	if needsSudo {
		// Try to install with sudo
		fmt.Fprintf(cmd.ErrOrStderr(), "Installing completion script to %s (requires sudo)...\n", installPath)

		// Create temp file
		tmpFile, err := os.CreateTemp("", "net-completion-*")
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error creating temp file: %v\n", err)
			return
		}
		defer os.Remove(tmpFile.Name())

		// Write completion script to temp file
		_, err = tmpFile.WriteString(content.String())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error writing to temp file: %v\n", err)
			return
		}
		tmpFile.Close()

		// Use sudo to copy to final location
		_, err = sysExecutor.Execute("sudo", "cp", tmpFile.Name(), installPath)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error installing completion script: %v\n", err)
			fmt.Fprintf(cmd.ErrOrStderr(), "Please install manually: sudo net completion %s > %s\n", shell, installPath)
			return
		}
	} else {
		// Install directly to user directory
		fmt.Fprintf(cmd.ErrOrStderr(), "Installing completion script to %s...\n", installPath)

		file, err := os.Create(installPath)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error creating completion file: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.WriteString(content.String())
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error writing completion script: %v\n", err)
			return
		}
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Completion script installed successfully!\n")

	// Print instructions for enabling completion
	switch shell {
	case "bash":
		fmt.Fprintf(cmd.ErrOrStderr(), "Restart your shell or run: source %s\n", installPath)
	case "zsh":
		fmt.Fprintf(cmd.ErrOrStderr(), "Add 'fpath=(~/.local/share/zsh/site-functions $fpath)' to your ~/.zshrc if not already present\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Then restart your shell or run: autoload -U compinit && compinit\n")
	case "fish":
		fmt.Fprintf(cmd.ErrOrStderr(), "Restart your shell to enable completions\n")
	}
}
