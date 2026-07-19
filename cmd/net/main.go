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
	"github.com/angelfreak/net/pkg/netlink"
	"github.com/angelfreak/net/pkg/network"
	"github.com/angelfreak/net/pkg/portal"
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
// valueFlags are global flags that take a separate value argument. When one
// appears in space-separated form (e.g. "--iface wlp1s0"), the following arg
// is its value, not the subcommand, and must be skipped when locating the
// subcommand — otherwise a root-exempt command like "net --iface X status"
// would be wrongly elevated via sudo.
var valueFlags = map[string]bool{"--config": true, "--iface": true}

func commandNeedsRoot() bool {
	return commandNeedsRootArgs(os.Args[1:])
}

func commandNeedsRootArgs(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// Global flags that don't need root
		if arg == "-h" || arg == "--help" || arg == "--version" || arg == "-v" {
			return false
		}
		// Skip flags. For a value-taking flag in space-separated form, also
		// skip its value so it isn't mistaken for the subcommand. The "--f=v"
		// form is a single arg and needs no extra skip.
		if strings.HasPrefix(arg, "-") {
			if valueFlags[arg] && i+1 < len(args) {
				i++
			}
			continue
		}
		// First positional arg is the subcommand — check if it's root-exempt
		switch arg {
		case "help", "completion", "status", "show", "list", "portal":
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

	// Setup signal handler for graceful cleanup on Ctrl+C / SIGTERM. Cleanup
	// only undoes state that an in-flight mutating command registered (see the
	// cleanupRegistry.register call sites in app.go) — read-only commands
	// register nothing, so interrupting a scan/list/status leaves a healthy
	// connection untouched.
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		// stage 2 propagates ctx to running executor calls so cleanup runs
		// against a settled command; cancel now so nothing new starts.
		cancel()
		if logger != nil {
			logger.Debug("Interrupt received, cleaning up")
		}
		fmt.Fprintln(os.Stderr, "interrupt received, cleaning up")
		// A second signal during cleanup means the user wants out now —
		// abandon remaining cleanup and exit immediately.
		go func() {
			<-sigCh
			os.Exit(130)
		}()
		defaultCleanups.run(5 * time.Second)
		os.Exit(130) // Standard exit code for SIGINT
	}()
	_ = ctx // stage 2 will pass this to ExecuteContext for cooperative cancel

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

	// Apply timeout config from YAML if available
	if config != nil {
		dhcpClientMgr.SetDHCPTimeout(config.Common.Timeouts.GetDHCPTimeout())
	}

	// Initialize managers
	wifiManager := wifi.NewManager(sysExecutor, logger, iface, dhcpClientMgr)
	if config != nil {
		wifiManager.SetAssociationTimeout(config.Common.Timeouts.GetAssociationTimeout())
	}
	wifiMgr = wifiManager
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
		PortalDet:  createPortalDetector(),
		RouteMgr:   netlink.NewRouteManager(),
		Interface:  iface,
		NoVPN:      noVPN,
		Debug:      debug,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
}

// createPortalDetector builds the portal detector from config. Config is
// loaded by PersistentPreRun (initializeManagers) before any command Run
// calls createApp, so the nil-config fallback only covers load failures.
func createPortalDetector() types.PortalDetector {
	probeURL := ""
	timeout := (&types.TimeoutConfig{}).GetPortalTimeout()
	if cfg := cfgManager.GetConfig(); cfg != nil {
		probeURL = cfg.Common.Portal.URL
		timeout = cfg.Common.Timeouts.GetPortalTimeout()
	}
	return portal.New(probeURL, timeout, logger)
}

// findDefaultInterface picks the primary network interface by reading sysfs
// directly (/sys/class/net), which needs no external binary. This matters
// because root-exempt commands like `net status` run without /sbin in PATH,
// where `iw`/`ip` may not resolve — the old shell-out silently fell through to
// the "wlan0" fallback and reported the wrong interface.
//
// Preference order: an up wireless interface, then any wireless interface,
// then an up wired interface, then any wired interface. VPN/virtual interfaces
// (wg*, tun*, tailscale*, docker*, veth*, br*) are ignored.
func findDefaultInterface() string {
	iface, why := selectDefaultInterface("/sys/class/net")
	if why != "" {
		logger.Debug("Selected default interface", "interface", iface, "reason", why)
	} else {
		logger.Debug("No network interface found, using fallback", "interface", iface)
	}
	return iface
}

// selectDefaultInterface implements findDefaultInterface's logic against a
// given sysfs root so it can be unit-tested. Returns the chosen interface and
// a short reason ("" when it fell back to the default).
func selectDefaultInterface(sysNet string) (iface, why string) {
	entries, err := os.ReadDir(sysNet)
	if err != nil {
		return "wlan0", ""
	}

	isUp := func(name string) bool {
		state, _ := os.ReadFile(sysNet + "/" + name + "/operstate")
		return strings.TrimSpace(string(state)) == "up"
	}
	isWireless := func(name string) bool {
		_, err := os.Stat(sysNet + "/" + name + "/wireless")
		return err == nil
	}
	isWired := func(name string) bool {
		for _, p := range []string{"eth", "enp", "enx", "eno", "ens", "em"} {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}

	var upWireless, anyWireless, upWired, anyWired string
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		switch {
		case isWireless(name):
			if anyWireless == "" {
				anyWireless = name
			}
			if upWireless == "" && isUp(name) {
				upWireless = name
			}
		case isWired(name):
			if anyWired == "" {
				anyWired = name
			}
			if upWired == "" && isUp(name) {
				upWired = name
			}
		}
	}

	for _, candidate := range []struct {
		iface, why string
	}{
		{upWireless, "up wireless"},
		{anyWireless, "wireless"},
		{upWired, "up wired"},
		{anyWired, "wired"},
	} {
		if candidate.iface != "" {
			return candidate.iface, candidate.why
		}
	}

	return "wlan0", ""
}
