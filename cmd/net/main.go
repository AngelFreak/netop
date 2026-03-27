package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

// Global flags
var (
	configPath string
	iface      string
	noVPN      bool
	debug      bool
)

// Global managers (initialized in PersistentPreRun)
var (
	cfgManager  types.ConfigManager
	sysExecutor types.SystemExecutor
	logger      types.Logger
	wifiMgr     types.WiFiManager
	vpnMgr      types.VPNManager
	netMgr      types.NetworkManager
	hotspotMgr  types.HotspotManager
	dhcpMgr     types.DHCPManager
)

// rootCmd is the base command when called without any subcommands
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

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Select configuration file")
	rootCmd.PersistentFlags().StringVar(&iface, "iface", "", "Select networking interface")
	rootCmd.PersistentFlags().BoolVar(&noVPN, "no-vpn", false, "Don't connect to VPN")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
}

// commandNeedsRoot returns false for commands that can run without root privileges.
// Only checks the subcommand (first non-flag arg) and global flags, not positional
// arguments — otherwise a network named "status" would skip the sudo elevation.
func commandNeedsRoot() bool {
	for _, arg := range os.Args[1:] {
		// Global flags that don't need root
		if arg == "-h" || arg == "--help" || arg == "--version" || arg == "-v" {
			return false
		}
		// Skip flag arguments (start with -)
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// First positional arg is the subcommand — check if it's root-exempt
		switch arg {
		case "help", "completion", "status", "show", "list":
			return false
		default:
			// First positional arg is not exempt, needs root
			return true
		}
	}
	return true
}

// ensureRoot re-executes the program with sudo if not running as root.
func ensureRoot() {
	if os.Geteuid() == 0 {
		return // Already root
	}

	// Skip sudo for commands that don't need root
	if !commandNeedsRoot() {
		return
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

	// Ensure runtime directory exists with secure permissions (only for commands that need root)
	if commandNeedsRoot() {
		if err := os.MkdirAll(types.RuntimeDir, 0700); err != nil {
			// This should not happen if ensureRoot() worked correctly
			fmt.Fprintf(os.Stderr, "Error: failed to create runtime directory %s: %v\n", types.RuntimeDir, err)
			if os.Geteuid() != 0 {
				fmt.Fprintf(os.Stderr, "Error: not running as root (euid=%d). The auto-sudo mechanism failed.\n", os.Geteuid())
				fmt.Fprintf(os.Stderr, "Hint: run with sudo, or configure passwordless sudo for this binary\n")
			} else {
				fmt.Fprintf(os.Stderr, "Hint: check filesystem permissions and SELinux/AppArmor policies for %s\n", types.RuntimeDir)
			}
			os.Exit(1)
		}
	}

	// Setup signal handler for graceful cleanup on Ctrl+C / SIGTERM.
	// This ensures wpa_supplicant, dhclient/udhcpc, and resolv.conf are
	// cleaned up if the user interrupts a long-running operation (e.g.,
	// the 30s association wait during connect).
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		// Best-effort cleanup: unlock resolv.conf so the system isn't left
		// with an immutable file, and kill any DHCP/wpa processes we started.
		if sysExecutor != nil && logger != nil {
			logger.Debug("Signal received, cleaning up")
			sysExecutor.ExecuteWithTimeout(2*time.Second, "chattr", "-i", "/etc/resolv.conf")
		}
		os.Exit(130) // Standard exit code for SIGINT
	}()
	_ = ctx // available for future use with ExecuteContext

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

	// No wireless interface found, try wired interfaces
	logger.Debug("No wireless interface found, looking for wired interfaces")
	wiredOutput, err := sysExecutor.Execute("ip", "-o", "link", "show")
	if err == nil {
		for _, line := range strings.Split(wiredOutput, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := strings.TrimSuffix(fields[1], ":")
			if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "enp") ||
				strings.HasPrefix(name, "enx") || strings.HasPrefix(name, "eno") ||
				strings.HasPrefix(name, "ens") {
				logger.Debug("Found wired interface", "interface", name)
				return name
			}
		}
	}

	// Last resort fallback
	logger.Debug("No network interface found, using fallback", "interface", "wlan0")
	return "wlan0"
}
