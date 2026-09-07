package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// App encapsulates all dependencies for testable CLI operations.
// It provides methods for each CLI command (list, scan, connect, etc.)
// that can be tested with mock implementations of the manager interfaces.
type App struct {
	// Managers for different subsystems
	Logger     types.Logger         // Structured logging
	Executor   types.SystemExecutor // Shell command execution
	ConfigMgr  types.ConfigManager  // YAML configuration management
	WiFiMgr    types.WiFiManager    // WiFi scanning and connection
	VPNMgr     types.VPNManager     // VPN connection management
	NetworkMgr types.NetworkManager // Network configuration (DNS, MAC, routes)
	HotspotMgr types.HotspotManager // WiFi hotspot management
	DHCPMgr    types.DHCPManager    // DHCP server management
	PortalDet  types.PortalDetector // Captive portal / connectivity probing
	RouteMgr   types.RouteManager   // Route inspection for multi-home signaling (nil-safe)

	// Runtime configuration
	Interface string // Primary network interface to use
	NoVPN     bool   // When true, skip automatic VPN connection
	Debug     bool   // Enable debug output
	JSON      bool   // Emit one JSON envelope on stdout instead of text (see output.go)

	// PortalRetryDelay is the settle delay before the one connect-time retry
	// when the first portal probe reports offline. Zero means the 500ms
	// default; tests set 1ms.
	PortalRetryDelay time.Duration

	// cleanups holds interrupt-cleanup actions for mutating commands. Nil means
	// the process-wide defaultCleanups the signal handler drains; tests inject
	// a private registry to assert registration without touching the global.
	cleanups *cleanupRegistry

	// Output streams for testability
	Stdout io.Writer // Standard output (default: os.Stdout)
	Stderr io.Writer // Standard error (default: os.Stderr)
}

// cleanupRegistry returns the registry for interrupt cleanups, defaulting to
// the process-wide one the signal handler drains.
func (a *App) cleanupRegistry() *cleanupRegistry {
	if a.cleanups != nil {
		return a.cleanups
	}
	return defaultCleanups
}

// printf writes formatted output to stdout. Silent in JSON mode: stdout then
// carries exactly one envelope, written by emit/emitError.
func (a *App) printf(format string, args ...interface{}) {
	if a.JSON {
		return
	}
	fmt.Fprintf(a.Stdout, format, args...)
}

// progress prints a progress message to stdout only when not in debug mode.
// In debug mode, detailed logs are already shown so progress messages are redundant.
func (a *App) progress(format string, args ...interface{}) {
	if !a.Debug && !a.JSON {
		fmt.Fprintf(a.Stdout, format, args...)
	}
}

// println writes a line to stdout. Silent in JSON mode (see printf).
func (a *App) println(args ...interface{}) {
	if a.JSON {
		return
	}
	fmt.Fprintln(a.Stdout, args...)
}

// errorf writes formatted output to stderr
func (a *App) errorf(format string, args ...interface{}) {
	fmt.Fprintf(a.Stderr, format, args...)
}

// maskSecret returns a masked version of a secret string.
// For strings longer than 4 characters, it shows the first 2 and last 2 characters
// with asterisks in between. For shorter strings, it returns "****".
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// attemptVPNConnect tries to connect to the specified VPN.
// On success, prints a confirmation message to stdout.
// On failure, logs the error and prints a warning to stderr.
func (a *App) attemptVPNConnect(vpnName string) {
	a.Logger.Info("Connecting to VPN", "vpn", vpnName)
	a.progress("Connecting to VPN '%s'...\n", vpnName)
	if err := a.VPNMgr.Connect(vpnName); err != nil {
		a.Logger.Error("Failed to connect to VPN", "error", err)
		a.errorf("Warning: VPN connection failed: %v\n", err)
	} else {
		a.printf("VPN connected!\n")
	}
}

// resolveVPNName resolves the VPN name for a network, handling inheritance:
//   - vpn: some-vpn → uses that VPN
//   - vpn: (empty)  → disables VPN (won't inherit from common)
//   - no vpn key    → inherits from common.vpn
//
// Returns "" when no VPN is configured or the config is nil. Replaces the
// former connectVPN (RunConnect was its only production caller and now calls
// attemptVPNConnect itself so the portal hint and the VPN attempt resolve the
// name exactly once).
func (a *App) resolveVPNName(networkName string) string {
	if a.ConfigMgr == nil {
		return ""
	}
	config := a.ConfigMgr.GetConfig()
	if config == nil {
		return ""
	}
	if netConfig, ok := config.Networks[networkName]; ok {
		return a.ConfigMgr.MergeWithCommon(networkName, &netConfig).VPN
	}
	return config.Common.VPN
}

// portalCheckEnabled reports whether automatic portal probing is enabled
// (a detector is wired and config doesn't say check: off).
func (a *App) portalCheckEnabled() bool {
	if a.PortalDet == nil {
		return false
	}
	if a.ConfigMgr != nil {
		cfg := a.ConfigMgr.GetConfig()
		if cfg == nil {
			// Config failed to load: the user's portal policy (check: off,
			// custom URL) is unknown — probing with substituted defaults
			// could report "ok" against their intent. The load error was
			// already surfaced by the loader; skip automatic probes.
			return false
		}
		if cfg.Common.Portal.CheckDisabled() {
			return false
		}
	}
	return true
}

// checkPortalAfterConnect probes for a captive portal right after a
// connection comes up on connectedIface. An initial "offline" gets one retry
// after a short settle delay — right after DHCP, routes/DNS can lag by a few
// hundred ms and a premature warning trains users to ignore it. When the
// default route egresses a different interface than the one just connected
// (dual-homed: wired metric 100 beats WiFi 600), the probe result describes
// the wrong path — say so instead of reporting a silent false "ok". When a
// VPN is configured (vpnConfigured), an offline verdict is expected on
// VPN-required networks, so the offline warning is demoted to debug — the
// upcoming VPN attempt is the meaningful signal. Never fatal — prints
// warnings to stderr only. Reports whether a portal was detected so
// RunConnect can add a VPN hint.
func (a *App) checkPortalAfterConnect(connectedIface string, vpnConfigured bool) bool {
	if !a.portalCheckEnabled() {
		return false
	}
	// Honest multi-home signaling: the probe follows the kernel's preferred
	// default route (lowest metric — wired 100 beats WiFi 600), which may
	// not be the just-connected interface. (This note is part of the
	// automatic portal check: check: off disables it together with the
	// probe it annotates.) Any outcome via the wrong link
	// misleads (false ok, false offline, or a portal URL for the wrong
	// network), so the note prints regardless of the probe result.
	// NB: RouteMgr.GetDefaultRoute() returns the FIRST default in the
	// netlink dump, not the preferred one — use preferredDefaultIface.
	// The comparison is IPv4-main-table only (ListRoutes' scope); the note
	// says "IPv4 default route" so a dual-stack IPv6 egress isn't overclaimed.
	if iface := a.preferredDefaultIface(); iface != "" && connectedIface != "" && iface != connectedIface {
		a.errorf("Note: the portal probe follows the preferred IPv4 default route (%s), not the just-connected %s — portal detection for %s is unreliable while %s stays preferred. Disable/unplug %s or open a browser while on %s.\n", iface, connectedIface, connectedIface, iface, iface, connectedIface)
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		// Check errors mean misconfiguration (e.g. https probe URL) — the
		// user asked for auto-checks, so a silent skip would look like "no
		// portal". Surface it, but never fail the connect.
		a.errorf("Warning: portal probe misconfigured: %v\n", err)
		return false
	}
	if result.Status == types.PortalStatusOffline {
		delay := a.PortalRetryDelay
		if delay == 0 {
			delay = 500 * time.Millisecond
		}
		time.Sleep(delay)
		retry, retryErr := a.PortalDet.Check()
		if retryErr != nil {
			// Transient detector failure on the retry: don't warn "offline"
			// based on a half-completed check.
			a.Logger.Debug("Portal re-check failed", "error", retryErr)
			return false
		}
		result = retry
	}
	switch result.Status {
	case types.PortalStatusPortal:
		if result.PortalURL != "" {
			a.errorf("Warning: captive portal detected — log in at: %s\n", result.PortalURL)
		} else {
			a.errorf("Warning: captive portal detected — open %s in a browser to log in\n", result.ProbeURL)
		}
		return true
	case types.PortalStatusOffline:
		if vpnConfigured {
			// VPN-required networks legitimately look offline pre-VPN;
			// warning here would be noise before the meaningful attempt.
			a.Logger.Debug("No internet before VPN attempt — VPN may provide connectivity")
		} else {
			a.errorf("Warning: no internet connectivity detected\n")
		}
	case types.PortalStatusOnline:
		// nothing to warn about
	default:
		// Unknown or any future status: fail closed, mirroring RunPortal
		// and RunStatus (#93) — a silent no-op here would read as a clean
		// connect with working internet.
		a.errorf("Warning: internet connectivity could not be determined\n")
	}
	return false
}

// RunList lists active network connections with their IP, gateway, and DNS info.
// Returns an error if the connection list cannot be retrieved.
func (a *App) RunList() error {
	connections, err := a.WiFiMgr.ListConnections()
	if err != nil {
		a.Logger.Error("Failed to list connections", "error", err)
		a.errorf("Error: %v\n", err)
		return a.fail("list", err)
	}

	if a.JSON {
		if connections == nil {
			connections = []types.Connection{}
		}
		return a.emit("list", listResult{Connections: connections})
	}

	if len(connections) == 0 {
		a.println("No active connections")
		return nil
	}

	for _, conn := range connections {
		a.printf("Interface: %s\n", conn.Interface)
		if conn.SSID != "" {
			a.printf("SSID: %s\n", conn.SSID)
		}
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

// RunScan scans for available WiFi networks and displays them.
// If showOpen is true, only open (unprotected) networks are shown.
func (a *App) RunScan(showOpen bool) error {
	a.progress("Scanning for networks...\n")

	networks, err := a.WiFiMgr.Scan()
	if err != nil {
		a.Logger.Error("Failed to scan networks", "error", err)
		a.errorf("Error: %v\n", err)
		return a.fail("scan", err)
	}

	shown := make([]types.WiFiNetwork, 0, len(networks))
	for _, network := range networks {
		if showOpen && network.Security != "Open" {
			continue
		}
		shown = append(shown, network)
	}

	if a.JSON {
		// SSIDs are attacker-controlled; the JSON encoder escapes control
		// characters, so the value round-trips intact without reaching the
		// terminal raw.
		return a.emit("scan", scanResult{Networks: shown})
	}

	a.progress("Found %d networks\n", len(shown))

	for _, network := range shown {
		// Scanned SSIDs are attacker-controlled over the air; sanitize before
		// printing to prevent terminal-escape injection.
		a.printf("%s (%s) - Signal: %d dBm - Security: %s\n",
			system.SanitizeForTerminal(network.SSID), network.BSSID, network.Signal, network.Security)
	}
	return nil
}

// RunConnect connects to a network by name or SSID.
// If name matches a configured network, uses that configuration (merged with common settings).
// Otherwise treats name as a direct SSID. Optionally connects to VPN after WiFi connection.
func (a *App) RunConnect(name, password string) error {
	a.Logger.Debug("Connect command called", "name", name)

	// Interrupt cleanups are registered only once this run is about to change
	// a specific link, never during preflight: a Ctrl-C before that point must
	// leave the user's existing connection and DNS alone. undo holds the
	// deregister funcs; settled() drops them at establishment so an interrupt
	// during the portal check or VPN bring-up keeps the connection (VPN-failure
	// semantics), and the defer covers error returns.
	var undo []func()
	settled := func() {
		for _, deregister := range undo {
			deregister()
		}
		undo = nil
	}
	defer settled()
	registerCleanup := func(name string, fn func()) {
		undo = append(undo, a.cleanupRegistry().register(name, fn))
	}

	// Disconnect any active VPN before connecting to new network
	// This prevents stale VPN routes/interfaces from interfering.
	// Skip if --no-vpn is set — user wants to keep their VPN alive.
	if !a.NoVPN {
		a.Logger.Debug("Disconnecting any active VPN before connecting")
		if err := a.VPNMgr.Disconnect(""); err != nil {
			a.Logger.Debug("No active VPN to disconnect", "error", err)
		}
	}

	// Check if it's a configured network
	a.Logger.Debug("Looking up network config", "name", name)
	networkConfig, err := a.ConfigMgr.GetNetworkConfig(name)
	configName := name
	var connectedIface string
	if err != nil {
		// A config that failed to load (parse/validation error) is different
		// from a name that simply isn't configured: don't silently degrade to
		// treating the name as an SSID — that skips MAC/DNS/VPN settings the
		// user thinks are applied. GetConfig() is nil only on load failure.
		if a.ConfigMgr.GetConfig() == nil {
			a.errorf("Error: configuration failed to load, refusing to treat '%s' as a plain SSID. Fix the config file and retry.\n", name)
			return fmt.Errorf("configuration not loaded: %w", err)
		}
		// The name wasn't a configured network key, but it may be the SSID of
		// one. A unique SSID match lets us apply that network's config (MAC,
		// DNS, VPN) instead of degrading to a plain SSID connection.
		cfg := a.ConfigMgr.GetConfig()
		var matches []string
		for netName, nc := range cfg.Networks {
			if nc.SSID == name {
				matches = append(matches, netName)
			}
		}
		if len(matches) == 1 {
			configName = matches[0]
			nc := cfg.Networks[configName] // copy: map values are not addressable
			networkConfig = &nc
			err = nil
			a.Logger.Info("SSID matches configured network, using its configuration", "ssid", name, "network", configName)
		} else if len(matches) > 1 {
			a.Logger.Warn("Multiple configured networks share this SSID, connecting as plain SSID", "ssid", name, "networks", strings.Join(matches, ", "))
		}
	}
	if err != nil {
		// Not configured, treat as SSID
		a.Logger.Debug("Network config not found, treating as direct SSID", "name", name, "error", err)
		a.Logger.Info("Connecting to SSID", "ssid", name)

		// Flush stale DNS before DHCP so external tools (netbird) don't retain their DNS
		a.NetworkMgr.ClearDNS()

		a.progress("Connecting to WiFi...\n")
		// From here the WiFi link is being changed: an interrupt must undo it.
		// WiFiMgr.Disconnect terminates wpa_supplicant + DHCP clients natively,
		// flushes addrs/routes, brings the iface down, and removes the temp
		// wpa config.
		registerCleanup("abort-connect", func() { _ = a.WiFiMgr.Disconnect() })
		err = a.WiFiMgr.Connect(name, password, "")
		if err != nil {
			a.Logger.Error("Failed to connect to WiFi", "error", err)
			a.errorf("Error: %v\n", err)
			return err
		}
		connectedIface = a.WiFiMgr.GetInterface()

		// LockDNS makes resolv.conf immutable — intentional persistent state on
		// success. Register the unlock BEFORE locking so an interrupt during a
		// later stage doesn't leave DNS permanently frozen. UnlockDNS also
		// drops the ownership marker LockDNS sets, so an aborted connect leaves
		// no claim that a later `net stop` would act on.
		registerCleanup("unlock-resolv.conf", func() { _ = a.NetworkMgr.UnlockDNS() })

		// Lock resolv.conf after DHCP writes DNS to prevent external tools
		// (like netbird) from overwriting with their own DNS servers
		a.NetworkMgr.LockDNS()
	} else {
		// Use configured network - merge with common settings first
		networkConfig = a.ConfigMgr.MergeWithCommon(configName, networkConfig)
		a.Logger.Debug("Found network config", "name", configName, "ssid", networkConfig.SSID, "mac", networkConfig.MAC)
		a.Logger.Info("Connecting to configured network", "name", configName)
		if password == "" {
			password = networkConfig.PSK
		}
		a.Logger.Debug("Using network config", "configSSID", networkConfig.SSID)
		wired := networkConfig.SSID == ""
		if !wired {
			a.progress("Connecting to WiFi...\n")
		} else {
			// Switching to wired — disconnect WiFi first so its stale default
			// route doesn't prevent DHCP from setting the correct gateway.
			a.Logger.Debug("Disconnecting WiFi before wired connection")
			if err := a.WiFiMgr.Disconnect(); err != nil {
				a.Logger.Debug("No active WiFi to disconnect", "error", err)
			}
			a.progress("Connecting to wired network...\n")
		}
		// ConnectToConfiguredNetwork is where this run starts changing the
		// link (flush, up, DHCP) and where it locks DNS: SetDNS for custom
		// servers, LockDNS after DHCP. Both cleanups go in before the call.
		// The abort follows the link type. For wired it reads
		// networkConfig.Interface at run time, which ConnectToConfiguredNetwork
		// fills in by auto-detection before it touches anything; if that has
		// not happened yet there is nothing to undo.
		registerCleanup("abort-connect", func() {
			if !wired {
				_ = a.WiFiMgr.Disconnect()
				return
			}
			if iface := networkConfig.Interface; iface != "" {
				_ = a.NetworkMgr.Disconnect(iface)
			}
		})
		registerCleanup("unlock-resolv.conf", func() { _ = a.NetworkMgr.UnlockDNS() })
		err = a.NetworkMgr.ConnectToConfiguredNetwork(networkConfig, password, a.WiFiMgr)
		if err != nil {
			a.Logger.Error("Failed to connect to configured network", "error", err)
			a.errorf("Error: %v\n", err)
			return err
		}
		// ConnectToConfiguredNetwork sets networkConfig.Interface via auto-detection
		connectedIface = networkConfig.Interface
	}

	// Display connection information (includes "Connected!" message)
	a.printConnectionInfo(connectedIface)

	// The link is established: the connect is complete for cleanup purposes.
	// Drop the cleanups now so an interrupt during the (read-only) portal
	// check or the VPN attempt keeps the connection and its DNS lock.
	settled()

	// Resolve the VPN name once, before the portal check, so the hint, the
	// offline-warning suppression, and the attempt can never disagree.
	vpnName := ""
	if !a.NoVPN {
		vpnName = a.resolveVPNName(configName)
	}

	portalDetected := a.checkPortalAfterConnect(connectedIface, vpnName != "")

	if vpnName != "" {
		if portalDetected {
			a.errorf("Note: the VPN may not come up until the portal login is complete.\n")
		}
		a.attemptVPNConnect(vpnName)
	}
	return nil
}

// printConnectionInfo displays connection details
func (a *App) printConnectionInfo(iface string) {
	a.println("Connected!")

	conn, err := a.NetworkMgr.GetConnectionInfo(iface)
	if err != nil {
		a.Logger.Debug("Failed to get connection info", "error", err)
		return
	}

	if conn.IP != nil {
		a.printf("  IP:      %s\n", conn.IP.String())
	}
	if conn.Gateway != nil {
		a.printf("  Gateway: %s\n", conn.Gateway.String())
	}
	if len(conn.DNS) > 0 {
		a.printf("  DNS:     %v\n", conn.DNS)
	}
}

// RunStop stops network services.
// If interfaces is empty, stops all services (hotspot, DHCP, VPN, WiFi, DNS).
// If interfaces are specified, only brings down those specific interfaces.
func (a *App) RunStop(interfaces []string) error {
	if len(interfaces) == 0 {
		// Stop all services
		a.Logger.Debug("Stopping all network services")

		var stoppedServices []string

		// Stop hotspot
		hotspotStatus, err := a.HotspotMgr.GetStatus()
		if err == nil && hotspotStatus != nil && hotspotStatus.Running {
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

		// Stop network (WiFi and wired). WiFi first so wpa_supplicant is
		// terminated cleanly, then DisconnectAll catches any other active
		// interfaces (e.g. a wired NIC with a live lease).
		a.Logger.Debug("Stopping network connection")
		if err := a.WiFiMgr.Disconnect(); err != nil {
			a.Logger.Debug("No active WiFi to disconnect", "error", err)
		}
		torn := a.NetworkMgr.DisconnectAll()
		if len(torn) > 0 {
			stoppedServices = append(stoppedServices, "Network ("+strings.Join(torn, ", ")+")")
		} else {
			stoppedServices = append(stoppedServices, "Network")
		}

		// Clear DNS configuration, but only if netop set it. If DHCP wrote
		// resolv.conf and we never locked it, leave it alone — stopping the
		// network shouldn't wipe out the system's pre-existing DNS state.
		a.Logger.Debug("Clearing DNS configuration")
		cleared, err := a.NetworkMgr.ClearDNSIfOwned()
		if err != nil {
			a.Logger.Debug("Failed to clear DNS", "error", err)
		} else if cleared {
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
		// Stop specific interfaces. Use NetworkMgr.Disconnect so DHCP clients
		// are killed, addresses/routes flushed, and the link brought down —
		// otherwise a zombie udhcpc keeps renewing on a down interface.
		var lastErr error
		for _, iface := range interfaces {
			a.Logger.Debug("Stopping interface", "interface", iface)
			if err := a.NetworkMgr.Disconnect(iface); err != nil {
				a.Logger.Error("Failed to stop interface", "interface", iface, "error", err)
				a.errorf("✗ Failed to stop %s\n", iface)
				lastErr = err
			} else {
				a.printf("✓ Stopped interface %s\n", iface)
			}
		}
		if lastErr != nil {
			return lastErr
		}
	}
	return nil
}

// RunDNS sets DNS servers or restores DHCP-provided DNS.
// If servers is empty or contains only "dhcp", performs DHCP renewal to restore DNS.
// Otherwise sets the specified DNS servers.
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

// RunMAC sets the MAC address on the primary interface.
// The mac parameter can be a specific address or "random" for randomization.
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

// RunVPN lists VPNs (arg == ""), disconnects all ("stop"), or connects to
// the named VPN.
func (a *App) RunVPN(arg string) error {
	if arg == "" {
		// List VPNs
		vpns, err := a.VPNMgr.ListVPNs()
		if err != nil {
			a.Logger.Error("Failed to list VPNs", "error", err)
			return a.fail("vpn", err)
		}

		if a.JSON {
			return a.emit("vpn", vpnListResult{VPNs: vpnEntries(vpns)})
		}

		if len(vpns) == 0 {
			a.println("No active VPNs")
			return nil
		}

		for _, v := range vpns {
			status := vpnStatusLabel(v)
			a.printf("%s (%s) - %s\n", v.Name, v.Type, status)
		}
		return nil
	}

	if a.JSON {
		return a.fail("vpn", errJSONUnsupported("vpn "+arg))
	}

	if arg == "stop" {
		err := a.VPNMgr.Disconnect("")
		if err != nil {
			a.Logger.Error("Failed to disconnect VPNs", "error", err)
			return err
		}
		a.println("✓ VPN disconnected")
	} else {
		a.progress("Connecting to VPN '%s'...\n", arg)
		err := a.VPNMgr.Connect(arg)
		if err != nil {
			a.Logger.Error("Failed to connect to VPN", "name", arg, "error", err)
			return err
		}
		a.printf("VPN connected!\n")
	}
	return nil
}

// RunGenkey generates a WireGuard private/public key pair and displays them.
func (a *App) RunGenkey() error {
	private, public, err := a.VPNMgr.GenerateWireGuardKey()
	if err != nil {
		a.Logger.Error("Failed to generate WireGuard key", "error", err)
		a.errorf("Error: %v\n", err)
		return a.fail("genkey", err)
	}

	if a.JSON {
		return a.emit("genkey", genkeyResult{PrivateKey: private, PublicKey: public})
	}

	a.println("✓ WireGuard keys generated")
	a.printf("Private key: %s\n", private)
	a.printf("Public key: %s\n", public)
	return nil
}

// RunShow displays configuration.
// If networkName is empty, shows all configuration (common settings, networks, VPNs).
// If networkName is specified, shows that network's config merged with common settings.
// Sensitive values like PSK are masked in the output.
func (a *App) RunShow(networkName string) error {
	if networkName == "" {
		// Show all configurations
		config := a.ConfigMgr.GetConfig()
		if config == nil {
			if a.JSON {
				// Text mode reports this and exits 0; an agent needs a
				// real failure so ok:false and the exit code agree.
				return a.fail("show", withCode(codeNotFound, fmt.Errorf("no configuration loaded")))
			}
			a.println("No configuration loaded")
			return nil
		}

		if a.JSON {
			return a.emit("show", newShowAllResult(config))
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
		return nil
	}

	// Show specific network
	config, err := a.ConfigMgr.GetNetworkConfig(networkName)
	if err != nil {
		a.Logger.Error("Failed to get network config", "name", networkName, "error", err)
		a.errorf("Error: %v\n", err)
		return a.fail("show", err)
	}

	merged := a.ConfigMgr.MergeWithCommon(networkName, config)

	if a.JSON {
		return a.emit("show", newShowNetworkResult(networkName, merged))
	}

	a.printf("Network: %s\n", networkName)
	if merged.Interface != "" {
		a.printf("Interface: %s\n", merged.Interface)
	}
	if merged.SSID != "" {
		a.printf("SSID: %s\n", merged.SSID)
	}
	if merged.PSK != "" {
		a.printf("PSK: %s\n", maskSecret(merged.PSK))
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
	return nil
}

// RunPortal probes for internet connectivity and captive portals, printing
// the portal login URL when one is detected. Returns the detected status so
// the CLI can map it to scripting-friendly exit codes; the status is only
// meaningful when err is nil.
func (a *App) RunPortal() (types.PortalStatus, error) {
	if a.PortalDet == nil {
		return types.PortalStatusOffline, fmt.Errorf("portal detection not available")
	}
	// GetConfig() is nil only when the config file failed to load/validate
	// (matches RunConnect's convention). Probing silently with the DEFAULT
	// URL would mask the user's broken portal config — surface it (exit 3).
	if a.ConfigMgr != nil && a.ConfigMgr.GetConfig() == nil {
		err := fmt.Errorf("configuration failed to load — fix the config file and retry")
		a.errorf("Error: %v\n", err)
		return types.PortalStatusOffline, err
	}
	result, err := a.PortalDet.Check()
	if err != nil {
		a.errorf("Error: %v\n", err)
		return types.PortalStatusOffline, err
	}
	// Like status (#128), every outcome names the probed route when known —
	// this command has no connect-time multi-home note either.
	routeSuffix := ""
	if iface := a.preferredDefaultIface(); iface != "" {
		routeSuffix = fmt.Sprintf(" (default IPv4 route: %s)", iface)
	}
	switch result.Status {
	case types.PortalStatusPortal:
		a.printf("Captive portal detected!%s\n", routeSuffix)
		if result.PortalURL != "" {
			a.printf("  Log in at: %s\n", result.PortalURL)
		} else {
			a.printf("  Open %s in a browser to trigger the portal login page\n", result.ProbeURL)
		}
	case types.PortalStatusOnline:
		a.printf("Internet: ok%s\n", routeSuffix)
	default:
		// Offline, Unknown, and any future status: never fail open into
		// "ok". Neutral copy — Offline covers both no-response and HTTP
		// error statuses from the probe endpoint.
		a.printf("Internet: unreachable%s\n", routeSuffix)
	}
	return result.Status, nil
}

// preferredDefaultIface returns the outgoing interface of the LOWEST-metric
// IPv4 default route — the kernel's preferred IPv4 path. Heuristic for the
// route labels and the connect-time honesty note only: the probe may resolve
// AAAA and egress IPv6 on a dual-stack host, which this cannot see
// (ListRoutes is IPv4 main table). Returns "" when unknown (nil RouteMgr,
// netlink error, or no default route). GetDefaultRoute is NOT used: it
// returns the first default in the netlink dump, which on a dual-homed
// machine may be the higher-metric one.
func (a *App) preferredDefaultIface() string {
	if a.RouteMgr == nil {
		return ""
	}
	routes, err := a.RouteMgr.ListRoutes()
	if err != nil {
		return ""
	}
	// ListRoutes is already scoped to the IPv4 main table; types.Route
	// carries no family/table/scope fields, so metric is the only selector
	// available. Ties keep the first seen (kernel dump order) — deterministic
	// per dump, and good enough for an advisory label.
	best := ""
	bestMetric := -1
	for _, r := range routes {
		if !r.IsDefault() || r.Iface == "" {
			continue
		}
		if bestMetric == -1 || r.Metric < bestMetric {
			best, bestMetric = r.Iface, r.Metric
		}
	}
	return best
}

// RunStatus shows the full network status: connection, internet reachability,
// VPNs, hotspot and DHCP server. Data is gathered first, then rendered as
// text or emitted as JSON, so both views come from the same facts.
func (a *App) RunStatus() error {
	st := a.gatherStatus()
	if a.JSON {
		return a.emit("status", st)
	}
	a.renderStatus(st)
	return nil
}

// gatherStatus collects every fact RunStatus reports. Failures of individual
// probes are recorded in the result rather than aborting, matching the text
// view where each section degrades independently.
func (a *App) gatherStatus() statusResult {
	st := statusResult{Interface: a.Interface, VPNs: []vpnEntry{}}

	conn, err := a.NetworkMgr.GetConnectionInfo(a.Interface)
	if err != nil {
		a.Logger.Debug("Failed to get connection info", "error", err)
	} else {
		st.Connection = conn
	}

	if hostname, err := os.Hostname(); err != nil {
		a.Logger.Debug("Failed to get hostname", "error", err)
	} else {
		st.Hostname = strings.TrimSpace(hostname)
	}

	if mac, err := a.NetworkMgr.GetMAC(a.Interface); err != nil {
		a.Logger.Debug("Failed to get MAC address", "error", err)
	} else {
		st.MAC = mac
		st.macKnown = true
		if config := a.ConfigMgr.GetConfig(); config != nil {
			policy := config.Common.MAC
			if policy == "random" || policy == "default" || strings.Contains(policy, "??") {
				st.MACPolicy = policy
			}
		}
	}

	// Internet reachability / captive portal (skipped when portal.check: off)
	if a.portalCheckEnabled() {
		inet := &internetResult{DefaultRoute: a.preferredDefaultIface()}
		result, err := a.PortalDet.Check()
		switch {
		case err != nil:
			// Misconfigured probe must be visible, not indistinguishable
			// from check: off. Labeled like every other outcome (#128).
			inet.Status = internetError
			inet.Error = err.Error()
		case result.Status == types.PortalStatusPortal:
			inet.Status = internetPortal
			inet.PortalURL = result.PortalURL
			if inet.PortalURL == "" {
				inet.PortalURL = result.ProbeURL
			}
		case result.Status == types.PortalStatusOnline:
			inet.Status = internetOK
		default:
			// Offline, Unknown, and any future status — never fail open.
			inet.Status = internetUnreachable
		}
		st.Internet = inet
	}

	if vpns, err := a.VPNMgr.ListVPNs(); err != nil {
		a.Logger.Debug("Failed to list VPNs", "error", err)
		st.VPNError = err.Error()
	} else {
		st.VPNs = vpnEntries(vpns)
	}

	if hs, err := a.HotspotMgr.GetStatus(); err != nil {
		a.Logger.Debug("Failed to get hotspot status", "error", err)
		st.HotspotError = err.Error()
	} else if hs.Running {
		st.Hotspot = hs
	}

	if st.DHCPServer.Running = a.DHCPMgr.IsRunning(); st.DHCPServer.Running {
		nat := a.DHCPMgr.NATStatus()
		st.DHCPServer.Sharing = &nat
	}
	return st
}

// renderStatus prints st in the human-readable layout.
func (a *App) renderStatus(st statusResult) {
	a.println("Network Status")
	a.println("==============")

	if st.Hostname != "" {
		a.printf("\nHostname:  %s\n", st.Hostname)
	}
	a.printf("Interface: %s\n", st.Interface)

	if st.macKnown {
		macInfo := st.MAC
		switch {
		case st.MACPolicy == "random":
			macInfo += " (random)"
		case st.MACPolicy == "default":
			macInfo += " (randomized Apple OUI)"
		case st.MACPolicy != "":
			macInfo += " (randomized from " + st.MACPolicy + ")"
		}
		a.printf("MAC:       %s\n", macInfo)
	}

	if conn := st.Connection; conn != nil {
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

	if inet := st.Internet; inet != nil {
		// Status has no connect-time route note, so every line names the
		// probed route when known — a portal/unreachable verdict via the
		// wrong link misleads just like a false ok. "IPv4" keeps the claim
		// at the heuristic's actual confidence. The probe is host-wide: it
		// follows the default route and is not scoped to Interface: above.
		route := ""
		if inet.DefaultRoute != "" {
			route = " (default IPv4 route: " + inet.DefaultRoute + ")"
		}
		switch inet.Status {
		case internetError:
			a.printf("Internet:  probe error (%s)%s\n", inet.Error, route)
		case internetPortal:
			a.printf("Internet:  captive portal (%s)%s\n", inet.PortalURL, route)
		case internetOK:
			if route == "" {
				route = " (default route)"
			}
			a.printf("Internet:  ok%s\n", route)
		default:
			a.printf("Internet:  unreachable%s\n", route)
		}
	}

	a.println("\nVPN")
	a.println("---")
	switch {
	case st.VPNError != "":
		a.println("(unable to query VPN status)")
	case len(st.VPNs) == 0:
		a.println("(none active)")
	default:
		for _, v := range st.VPNs {
			a.printf("%s (%s): %s\n", v.Name, v.Type, vpnStatusLabel(v.VPNStatus))
			if v.Interface != "" {
				a.printf("  Interface: %s\n", v.Interface)
			}
		}
	}

	a.println("\nHotspot")
	a.println("-------")
	switch {
	case st.HotspotError != "":
		a.println("(unable to query hotspot status)")
	case st.Hotspot == nil:
		a.println("(not running)")
	default:
		a.printf("SSID:      %s\n", st.Hotspot.SSID)
		a.printf("Interface: %s\n", st.Hotspot.Interface)
		if st.Hotspot.Gateway != nil {
			a.printf("Gateway:   %s\n", st.Hotspot.Gateway.String())
		}
		a.printf("Clients:   %d\n", st.Hotspot.Clients)
	}

	a.println("\nDHCP Server")
	a.println("-----------")
	if st.DHCPServer.Running {
		a.println("running")
		a.printf("Sharing:   %s\n", sharingLabel(*st.DHCPServer.Sharing))
	} else {
		a.println("(not running)")
	}
}

// sharingLabel renders a NAT verdict for status output. An unknown reason
// (state written by an older version) gets no empty parentheses.
func sharingLabel(nat types.NATState) string {
	switch {
	case nat.Active:
		return "via " + nat.OutInterface
	case nat.Reason != "":
		return "NOT active (" + nat.Reason + ")"
	default:
		return "NOT active"
	}
}

// RunHotspot manages the WiFi hotspot.
// Actions: "start" (requires config), "stop", "status".
// For security, the hotspot password is not displayed in output.
func (a *App) RunHotspot(action string, config *types.HotspotConfig) error {
	switch action {
	case "start":
		if config == nil {
			a.errorf("Configuration required for start action\n")
			return fmt.Errorf("configuration required")
		}
		a.progress("Starting hotspot...\n")
		err := a.HotspotMgr.Start(config)
		if err != nil {
			a.Logger.Error("Failed to start hotspot", "error", err)
			a.errorf("Failed to start hotspot: %v\n", err)
			return err
		}
		a.printf("Hotspot '%s' started!\n", config.SSID)
		a.printf("  SSID:     %s\n", config.SSID)
		if config.Password != "" {
			a.printf("  Security: WPA2 (password protected)\n")
		} else {
			a.printf("  Security: Open\n")
		}
		a.printf("  Gateway:  %s\n", config.Gateway)

	case "stop":
		err := a.HotspotMgr.Stop()
		if err != nil {
			a.Logger.Error("Failed to stop hotspot", "error", err)
			a.errorf("Failed to stop hotspot: %v\n", err)
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
		a.errorf("Unknown action: %s\n", action)
		return fmt.Errorf("unknown action: %s", action)
	}
	return nil
}

// RunDHCPServer manages the DHCP server for hotspot mode.
// Actions: "start" (requires config), "stop", "status".
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
			a.errorf("Failed to start DHCP server: %v\n", err)
			return err
		}
		a.printf("✓ DHCP server started successfully\n")
		a.printf("  Interface: %s\n", config.Interface)
		a.printf("  Gateway:   %s\n", config.Gateway)
		a.printf("  IP Range:  %s\n", config.IPRange)
		a.printf("  Lease:     %s\n", config.LeaseTime)

		// Internet sharing is the reason most people run this command, and it can
		// fail independently of the server starting. Say so plainly instead of
		// leaving the user to discover it from a client with no connectivity.
		nat := a.DHCPMgr.NATStatus()
		if nat.Active {
			a.printf("  Sharing:   via %s\n", nat.OutInterface)
		} else {
			a.errorf("\n⚠ Internet sharing is NOT active: %s\n", nat.Reason)
			a.errorf("  Clients will get an IP address but will not reach the internet.\n")
			a.errorf("  Check that another interface has a default route, then re-run.\n")
		}

	case "stop":
		err := a.DHCPMgr.Stop()
		if err != nil {
			a.Logger.Error("Failed to stop DHCP server", "error", err)
			a.errorf("Failed to stop DHCP server: %v\n", err)
			return err
		}
		a.println("✓ DHCP server stopped successfully")

	case "status":
		if !a.DHCPMgr.IsRunning() {
			a.println("DHCP server is not running")
			return nil
		}
		a.println("DHCP server is running")
		if cfg := a.DHCPMgr.GetCurrentConfig(); cfg != nil {
			a.printf("  Interface: %s\n", cfg.Interface)
			a.printf("  Gateway:   %s\n", cfg.Gateway)
			a.printf("  IP Range:  %s\n", cfg.IPRange)
		}
		a.printf("  Sharing:   %s\n", sharingLabel(a.DHCPMgr.NATStatus()))
		leases, err := a.DHCPMgr.GetLeases()
		if err != nil {
			a.Logger.Warn("Failed to read leases", "error", err)
		}
		if len(leases) == 0 {
			a.println("\n(no active leases)")
		} else {
			a.printf("\n%-17s  %-15s  %-20s  %s\n", "MAC", "IP", "HOSTNAME", "EXPIRES")
			for _, l := range leases {
				// Lease hostnames come from LAN DHCP clients; sanitize before
				// printing to prevent terminal-escape injection.
				hostname := system.SanitizeForTerminal(l.Hostname)
				if hostname == "" {
					hostname = "-"
				}
				a.printf("%-17s  %-15s  %-20s  %s\n", l.MAC, l.IP, hostname, l.Expiry.Format("2006-01-02 15:04"))
			}
		}

	default:
		a.errorf("Unknown action: %s\n", action)
		return fmt.Errorf("unknown action: %s", action)
	}
	return nil
}

// vpnStatusLabel renders a VPN's connection state for display.
//
// An ambiguous entry is one where the daemon reports a tunnel up but the
// responsible config entry cannot be identified — printing "disconnected"
// there would contradict the daemon, so say what is actually known.
func vpnStatusLabel(v types.VPNStatus) string {
	switch {
	case v.Connected:
		return "connected"
	case v.Ambiguous:
		return "disconnected? (a " + v.Type + " tunnel is up; run as root to identify which profile)"
	default:
		return "disconnected"
	}
}
