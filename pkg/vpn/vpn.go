package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/angelfreak/net/pkg/netlink"
	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
	"golang.org/x/crypto/curve25519"
)

// curve25519Basepoint is the standard basepoint for X25519 key derivation
var curve25519Basepoint = [32]byte{9}

// Manager implements the VPNManager interface
type Manager struct {
	executor      types.SystemExecutor
	logger        types.Logger
	configMgr     types.ConfigManager
	routeMgr      types.RouteManager // netlink-backed routing table access (gateway detection, route restore)
	addrMgr       types.AddrManager  // netlink-backed interface address access (WireGuard iface IP)
	linkMgr       types.LinkManager  // netlink-backed link access (WireGuard iface create/delete/enumerate)
	endpointRoute string             // Stores the VPN endpoint IP for cleanup on disconnect
	runtimeDir    string             // Directory for runtime files (active-vpn state file)
	mu            sync.Mutex         // Protects endpointRoute and serializes Connect/Disconnect/state file operations

	// Status verification polling for daemon-based VPNs (tailscale, netbird).
	// Their "up" command can return before the tunnel is established, so we
	// poll status until it reports connected. Overridable in tests.
	verifyAttempts int
	verifyDelay    time.Duration
}

// vpnState holds the state information stored in the active-vpn file
// Format: vpn-name|interface|type|originalGateway|originalInterface|endpointRoute
type vpnState struct {
	Name              string
	Interface         string
	Type              string
	OriginalGateway   string
	OriginalInterface string
	EndpointRoute     string
}

// NewManager creates a new VPN manager with the default runtime directory
func NewManager(executor types.SystemExecutor, logger types.Logger, configMgr types.ConfigManager) *Manager {
	return NewManagerWithDir(executor, logger, configMgr, types.RuntimeDir)
}

// NewManagerWithDir creates a new VPN manager with a custom runtime directory
func NewManagerWithDir(executor types.SystemExecutor, logger types.Logger, configMgr types.ConfigManager, runtimeDir string) *Manager {
	return &Manager{
		executor:       executor,
		logger:         logger,
		configMgr:      configMgr,
		routeMgr:       netlink.NewRouteManager(),
		addrMgr:        netlink.NewAddrManager(),
		linkMgr:        netlink.NewLinkManager(),
		runtimeDir:     runtimeDir,
		verifyAttempts: 30,
		verifyDelay:    time.Second,
	}
}

// Connect connects to a VPN
func (m *Manager) Connect(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Connecting to VPN", "name", name)

	// If already connected to a VPN, disconnect first to avoid corrupting
	// the saved gateway state. Without this, origGW would capture the VPN's
	// gateway instead of the physical one, making disconnect unable to
	// restore the correct route.
	existingState := m.getActiveVPNState()
	if existingState != nil && existingState.Type != "" {
		m.logger.Info("Disconnecting existing VPN before connecting new one", "existing", existingState.Name)
		// A failed teardown is fatal: proceeding would wipe the old VPN's
		// state while its tunnel may still be up, leaving it untracked.
		if err := m.disconnectTracked(existingState); err != nil {
			return fmt.Errorf("cannot disconnect active VPN '%s' before connecting '%s': %w", existingState.Name, name, err)
		}
		// Remove the old VPN's protective endpoint route and restore the
		// original route before saving new state, mirroring Disconnect — else
		// the old /32 endpoint route leaks permanently.
		m.removeEndpointRoute(existingState)
		m.restoreDefaultRouteFromState(existingState)
		m.clearActiveVPN()
	}

	// Load VPN config from ConfigManager
	config, err := m.configMgr.GetVPNConfig(name)
	if err != nil {
		return fmt.Errorf("failed to load VPN config '%s': %w", name, err)
	}

	// Save current default gateway BEFORE connecting
	// This will be used to restore the route after disconnect
	origGW, origIface := m.getCurrentGateway()

	// Reset the endpoint route tracker; connectWireGuard sets it when it
	// adds a protective route to the VPN endpoint.
	m.endpointRoute = ""

	var connectErr error
	var vpnIface string
	switch config.Type {
	case "openvpn":
		connectErr = m.connectOpenVPN(config)
		vpnIface = openVPNDevice(config.Config)
	case "wireguard":
		connectErr = m.connectWireGuard(config, origGW, origIface)
		vpnIface = config.Interface
		if vpnIface == "" {
			vpnIface = "wg0"
		}
	case "tailscale":
		if !m.executor.HasCommand("tailscale") {
			return fmt.Errorf("tailscale CLI not found. Install it: https://tailscale.com/download/linux")
		}
		connectErr = m.connectTailscale(config)
		vpnIface = "tailscale0"
	case "netbird":
		if !m.executor.HasCommand("netbird") {
			return fmt.Errorf("netbird CLI not found. Install it: https://docs.netbird.io/how-to/installation")
		}
		connectErr = m.connectNetBird(config)
		vpnIface = "wt0"
	default:
		return fmt.Errorf("unsupported VPN type: %s", config.Type)
	}

	if connectErr != nil {
		return connectErr
	}

	// Record the active VPN state for status tracking and proper disconnect.
	// The endpoint route is persisted because the CLI is one-shot: the process
	// that disconnects is not the one that connected, so in-memory state alone
	// would leak the protective endpoint route.
	state := vpnState{
		Name:              name,
		Interface:         vpnIface,
		Type:              config.Type,
		OriginalGateway:   origGW,
		OriginalInterface: origIface,
		EndpointRoute:     m.endpointRoute,
	}
	if err := m.setActiveVPNState(state); err != nil {
		m.logger.Debug("Failed to record active VPN state", "error", err)
		// Non-fatal: connection succeeded, just status tracking won't work perfectly
	}

	return nil
}

// Disconnect disconnects from a VPN
func (m *Manager) Disconnect(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Disconnecting from VPN", "name", name)

	// Read the VPN state to know exactly what to clean up
	state := m.getActiveVPNState()

	// When a specific VPN is named, only disconnect if it is the active one
	if name != "" && state != nil && state.Name != "" && state.Name != name {
		return fmt.Errorf("VPN '%s' is not the active VPN (currently active: '%s')", name, state.Name)
	}

	var disconnectErr error

	// Disconnect based on tracked state (process isolation)
	if state != nil && state.Type != "" {
		m.logger.Debug("Using tracked VPN state for disconnect", "type", state.Type, "interface", state.Interface)
		disconnectErr = m.disconnectTracked(state)
	} else if state != nil {
		// State file exists but no type — legacy format
		m.logger.Debug("Legacy VPN state, using legacy disconnect")
		m.disconnectLegacy()
	} else {
		// No state file at all — no VPN was connected via net
		m.logger.Debug("No active VPN to disconnect")
		return fmt.Errorf("no active VPN connection")
	}

	// If bringing the VPN down failed, keep the routes and state file intact so
	// the user can retry "net vpn stop" instead of being stranded with a live
	// tunnel and no way to tear it down.
	if disconnectErr != nil {
		return disconnectErr
	}

	// Remove the VPN endpoint route if we added one.
	m.removeEndpointRoute(state)

	// Restore default route via the physical interface using saved original route
	m.restoreDefaultRouteFromState(state)

	// Clear the active VPN state file
	m.clearActiveVPN()

	return nil
}

// disconnectTracked disconnects using tracked state (process isolation)
func (m *Manager) disconnectTracked(state *vpnState) error {
	switch state.Type {
	case "openvpn":
		// Kill only our OpenVPN process using PID file
		pidFile := filepath.Join(m.runtimeDir, "openvpn.pid")
		if err := system.KillProcessByPID(m.executor, m.logger, pidFile); err != nil {
			m.logger.Warn("Failed to kill tracked OpenVPN", "error", err)
			return fmt.Errorf("failed to stop OpenVPN: %w", err)
		}
		// Bring down the tunnel interface recorded at connect time
		iface := state.Interface
		if iface == "" {
			iface = "tun0"
		}
		if err := m.linkMgr.SetDown(iface); err != nil {
			m.logger.Debug("Failed to bring down OpenVPN interface", "interface", iface, "error", err)
		}
	case "wireguard":
		// Delete only our WireGuard interface
		iface := state.Interface
		if iface == "" {
			iface = "wg0"
		}
		if err := m.linkMgr.Delete(iface); err != nil {
			// The delete may fail because the interface is already gone. Probe
			// for it; if it is truly absent there is nothing to tear down, so
			// treat the disconnect as successful rather than trapping the user.
			if exists, probeErr := m.linkMgr.Exists(iface); probeErr != nil || !exists {
				m.logger.Debug("WireGuard interface already gone", "interface", iface)
				return nil
			}
			m.logger.Warn("Failed to delete WireGuard interface", "interface", iface, "error", err)
			return fmt.Errorf("failed to delete WireGuard interface %s: %w", iface, err)
		}
	case "tailscale":
		if _, err := m.executor.ExecuteWithTimeout(10*time.Second, "tailscale", "down"); err != nil {
			m.logger.Warn("Failed to disconnect Tailscale", "error", err)
			return fmt.Errorf("failed to disconnect Tailscale: %w", err)
		}
	case "netbird":
		if _, err := m.executor.ExecuteWithTimeout(10*time.Second, "netbird", "down"); err != nil {
			m.logger.Warn("Failed to disconnect NetBird", "error", err)
			return fmt.Errorf("failed to disconnect NetBird: %w", err)
		}
	}
	return nil
}

// disconnectLegacy disconnects using legacy behavior (kills all VPN processes)
// This is used for backwards compatibility when no state file exists
func (m *Manager) disconnectLegacy() {
	// Kill OpenVPN processes with SIGKILL fallback
	m.killProcess("openvpn")

	// Collect WireGuard interfaces to tear down (netlink enumeration by type).
	wgInterfaces, err := m.linkMgr.ListByType("wireguard")
	if err != nil {
		m.logger.Debug("Failed to list WireGuard interfaces", "error", err)
		wgInterfaces = nil
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
				if err := m.linkMgr.Delete(ifaceName); err != nil {
					m.logger.Debug("Failed to delete WireGuard interface", "interface", ifaceName, "error", err)
				}
			} else {
				// For tun/tap, just bring it down
				if err := m.linkMgr.SetDown(ifaceName); err != nil {
					m.logger.Debug("Failed to bring down interface", "interface", ifaceName, "error", err)
				}
			}
		}(iface)
	}
	wg.Wait()

	// Also try to disconnect Tailscale and NetBird if their CLIs are available
	if m.executor.HasCommand("tailscale") {
		if _, err := m.executor.ExecuteWithTimeout(10*time.Second, "tailscale", "down"); err != nil {
			m.logger.Debug("Failed to disconnect Tailscale (legacy)", "error", err)
		}
	}
	if m.executor.HasCommand("netbird") {
		if _, err := m.executor.ExecuteWithTimeout(10*time.Second, "netbird", "down"); err != nil {
			m.logger.Debug("Failed to disconnect NetBird (legacy)", "error", err)
		}
	}
}

// removeEndpointRoute removes the protective /32 route to a WireGuard VPN
// endpoint that connectWireGuard may have added. Prefers the persisted route
// from the state file — the connecting process is usually not the one tearing
// down, so the in-memory value is only a same-process fallback.
func (m *Manager) removeEndpointRoute(state *vpnState) {
	endpointRoute := m.endpointRoute
	if state != nil && state.EndpointRoute != "" {
		endpointRoute = state.EndpointRoute
	}
	m.endpointRoute = ""
	if endpointRoute != "" {
		m.logger.Debug("Removing VPN endpoint route", "endpoint", endpointRoute)
		_ = m.routeMgr.DelRoute(endpointRoute)
	}
}

// restoreDefaultRouteFromState restores the default route using saved state
func (m *Manager) restoreDefaultRouteFromState(state *vpnState) {
	// A route is restorable as long as we know its outgoing interface. The
	// gateway may legitimately be empty for a device-only default route (e.g.
	// the original route was `default dev wg0`). Branching on interface (not
	// gateway) is what lets device-only routes be restored instead of silently
	// dropped.
	if state != nil && state.OriginalInterface != "" {
		m.logger.Debug("Restoring default route from saved state",
			"gateway", state.OriginalGateway, "interface", state.OriginalInterface)
		if err := m.routeMgr.ReplaceDefault(state.OriginalInterface, state.OriginalGateway, 0); err != nil {
			m.logger.Debug("Failed to restore default route from state", "error", err)
			// Fall back to heuristic detection
			m.restoreDefaultRoute()
		}
		return
	}

	// No saved state, use heuristic detection
	m.restoreDefaultRoute()
}

// restoreDefaultRoute finds the physical network interface and restores the default route
// This is the legacy/fallback method when no saved state is available
func (m *Manager) restoreDefaultRoute() {
	// Find a route via a physical interface (VPN endpoint routes point to the
	// original gateway). Skip VPN interfaces so we don't restore the tunnel we
	// just tore down.
	routes, err := m.routeMgr.ListRoutes()
	if err != nil {
		m.logger.Debug("Failed to get routes", "error", err)
		return
	}

	var gateway, iface string

	// Look for routes that have a gateway ("via") on a physical interface —
	// these point to the original upstream gateway.
	for _, r := range routes {
		if r.Gw == "" || r.Iface == "" {
			continue
		}

		if isVPNInterface(r.Iface) {
			continue
		}

		// Found a route with gateway via physical interface.
		gateway = r.Gw
		iface = r.Iface
		break
	}

	if gateway == "" || iface == "" {
		m.logger.Debug("Could not determine original gateway")
		return
	}

	// Restore default route
	m.logger.Debug("Restoring default route", "gateway", gateway, "interface", iface)
	if err := m.routeMgr.ReplaceDefault(iface, gateway, 0); err != nil {
		m.logger.Debug("Failed to restore default route", "error", err)
	}
}

// isVPNInterface reports whether an interface name looks like a VPN tunnel
// (WireGuard, OpenVPN, Tailscale, NetBird), which should be skipped when
// searching for the original physical upstream route.
func isVPNInterface(iface string) bool {
	return strings.HasPrefix(iface, "wg") || strings.HasPrefix(iface, "tun") ||
		strings.HasPrefix(iface, "tailscale") || strings.HasPrefix(iface, "wt") ||
		strings.HasPrefix(iface, "utun")
}

// killProcess kills processes matching a pattern, with SIGKILL fallback if graceful shutdown fails
func (m *Manager) killProcess(pattern string) {
	system.KillProcessGraceful(m.executor, m.logger, pattern)
}

// ListVPNs lists available VPNs and their status
func (m *Manager) ListVPNs() ([]types.VPNStatus, error) {
	m.logger.Debug("Listing VPNs")

	// Read the active VPN name from state file (authoritative source)
	// Lock and use getActiveVPNState to parse the enhanced format
	m.mu.Lock()
	state := m.getActiveVPNState()
	activeVPN := ""
	if state != nil {
		activeVPN = state.Name
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

	// Check WireGuard interfaces: enumerate by type via netlink, then verify
	// each is actually configured (has peers) via `wg show` — a stale interface
	// will have no peers.
	wgIfaces, err := m.linkMgr.ListByType("wireguard")
	if err != nil {
		m.logger.Debug("Failed to list WireGuard interfaces", "error", err)
	}
	for _, iface := range wgIfaces {
		wgShowOutput, err := m.executor.ExecuteWithTimeout(2*time.Second, "wg", "show", iface)
		if err == nil && strings.Contains(wgShowOutput, "peer:") {
			runningWireGuard[iface] = true
		}
	}

	// Check Tailscale status
	runningTailscale := false
	tsOutput, tsErr := m.executor.ExecuteWithTimeout(2*time.Second, "tailscale", "status", "--json")
	if tsErr == nil && tailscaleStatusRunning(tsOutput) {
		runningTailscale = true
	}

	// Check NetBird status
	runningNetBird := false
	nbOutput, nbErr := m.executor.ExecuteWithTimeout(2*time.Second, "netbird", "status", "--json")
	if nbErr == nil && netBirdStatusConnected(nbOutput) {
		runningNetBird = true
	}

	// liveConnected reports whether a VPN of the given type is actually up
	// right now, based on the probes above.
	liveConnected := func(vpnType, iface string) bool {
		switch vpnType {
		case "openvpn":
			return runningOpenVPN
		case "wireguard":
			if iface == "" {
				iface = "wg0"
			}
			return runningWireGuard[iface]
		case "tailscale":
			return runningTailscale
		case "netbird":
			return runningNetBird
		}
		return false
	}

	var vpns []types.VPNStatus

	// Get configured VPNs from config
	config := m.configMgr.GetConfig()
	if config != nil && config.VPN != nil {
		// Count configs per daemon-based type. Tailscale/NetBird/OpenVPN each
		// run a single global daemon, so live detection can't tell which of
		// several same-type configs is actually up. When more than one exists
		// and no state file names the active one, marking them all "connected"
		// would lie — so we don't guess. WireGuard is exempt: it's keyed by a
		// distinct interface, so live detection is unambiguous.
		typeCount := make(map[string]int)
		for _, vc := range config.VPN {
			if vc.Type != "wireguard" {
				typeCount[vc.Type]++
			}
		}

		for name, vpnConfig := range config.VPN {
			status := types.VPNStatus{
				Name:      name,
				Type:      vpnConfig.Type,
				Connected: false,
				Interface: vpnConfig.Interface,
			}

			// Determine connection status:
			// 1. If we have an active VPN recorded, it names which VPN net
			//    connected — but verify it is actually still up, since daemons
			//    crash and sessions expire after the state file was written.
			// 2. Otherwise fall back to live detection (for VPNs started outside net)
			iface := vpnConfig.Interface
			if state != nil && name == activeVPN && state.Interface != "" {
				iface = state.Interface
			}
			if activeVPN != "" {
				status.Connected = name == activeVPN && liveConnected(vpnConfig.Type, iface)
			} else if typeCount[vpnConfig.Type] > 1 {
				// Ambiguous: multiple same-type daemon VPNs, none tracked.
				// Report disconnected rather than falsely flag all as up.
				status.Connected = false
			} else {
				status.Connected = liveConnected(vpnConfig.Type, iface)
			}

			if status.Interface == "" {
				switch vpnConfig.Type {
				case "openvpn":
					status.Interface = "tun0"
				case "wireguard":
					status.Interface = "wg0"
				case "tailscale":
					status.Interface = "tailscale0"
				case "netbird":
					status.Interface = "wt0"
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

// tailscaleStatusRunning reports whether "tailscale status --json" output
// shows the backend in the Running state.
func tailscaleStatusRunning(output string) bool {
	var st struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal([]byte(output), &st); err != nil {
		return strings.Contains(output, `"BackendState":"Running"`)
	}
	return st.BackendState == "Running"
}

// netBirdStatusConnected reports whether "netbird status --json" output shows
// the daemon connected to the management service. The peer entries also carry
// "Connected"/"Connecting" status strings, so a plain substring match would
// report the wrong thing — daemonStatus is the client-level signal.
func netBirdStatusConnected(output string) bool {
	var st struct {
		DaemonStatus string `json:"daemonStatus"`
	}
	if err := json.Unmarshal([]byte(output), &st); err != nil {
		return strings.Contains(output, `"daemonStatus":"Connected"`)
	}
	return st.DaemonStatus == "Connected"
}

// waitForVPNStatus polls a VPN CLI's status command until connected(output)
// reports true, retrying up to verifyAttempts times with verifyDelay between
// checks. Daemon-based VPNs (tailscale, netbird) establish the tunnel
// asynchronously after "up" returns, so a single immediate check races the daemon.
func (m *Manager) waitForVPNStatus(cli string, statusArgs []string, connected func(string) bool) error {
	var lastOutput string
	var lastErr error
	attempts := m.verifyAttempts
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(m.verifyDelay)
		}
		output, err := m.executor.ExecuteWithTimeout(5*time.Second, cli, statusArgs...)
		if err == nil && connected(output) {
			return nil
		}
		lastOutput = output
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("%s status check failed: %w", cli, lastErr)
	}
	return fmt.Errorf("%s tunnel did not come up (last status: %s)", cli, strings.TrimSpace(lastOutput))
}

// connectTailscale connects using the Tailscale CLI
func (m *Manager) connectTailscale(config *types.VPNConfig) error {
	m.logger.Info("Connecting to Tailscale")

	// Switch profile if specified (for multi-account support).
	// "tailscale switch" may return a non-zero exit code even on success
	// (e.g. empty stderr), so only a failure with a real message counts.
	// A real failure is fatal: proceeding would bring up the tunnel on
	// whatever account is currently active — silently wrong for multi-account.
	if config.Profile != "" {
		m.logger.Debug("Switching Tailscale profile", "profile", config.Profile)
		_, err := m.executor.ExecuteWithTimeout(10*time.Second, "tailscale", "switch", config.Profile)
		if err != nil && !isEmptyStderrError(err) {
			return fmt.Errorf("failed to switch Tailscale profile %q: %w (check 'tailscale switch --list'; net runs as root, so the profile must be visible to root)", config.Profile, err)
		}
	}

	// Bring the interface up first. When an authkey is provided we pass it
	// here so the node can register; otherwise a bare "up" just ensures the
	// daemon is running (it won't block if already authenticated).
	//
	// The key is passed via "file:<path>" (a 0600 file) rather than as an argv
	// token so it isn't exposed through `ps` / process inspection.
	upArgs := []string{"up"}
	if config.AuthKey != "" {
		keyPath, cleanup, err := m.writeSecretFile("tailscale-authkey", config.AuthKey)
		if err != nil {
			return fmt.Errorf("failed to stage Tailscale auth key: %w", err)
		}
		defer cleanup()
		upArgs = append(upArgs, "--auth-key=file:"+keyPath)
	}

	_, err := m.executor.ExecuteWithTimeout(30*time.Second, "tailscale", upArgs...)
	if err != nil {
		return fmt.Errorf("failed to connect Tailscale: %w", err)
	}

	// Apply settings via "tailscale set" which changes individual prefs
	// without requiring all non-default flags (unlike "up").
	// Always pass explicit values so `tailscale set` resets prefs that were
	// dropped from the config. `set` persists prefs across sessions, so an
	// omitted flag would silently keep a previous session's exit-node or
	// accepted routes rather than clearing them. An empty --exit-node= clears
	// any existing exit node.
	setArgs := []string{
		"set",
		"--accept-dns=false",
		"--exit-node=" + config.ExitNode,
		fmt.Sprintf("--accept-routes=%t", config.AcceptRoutes),
	}

	if _, err := m.executor.ExecuteWithTimeout(10*time.Second, "tailscale", setArgs...); err != nil {
		return fmt.Errorf("failed to apply Tailscale settings: %w", err)
	}

	// Verify the tunnel actually came up before reporting success
	if err := m.waitForVPNStatus("tailscale", []string{"status", "--json"}, tailscaleStatusRunning); err != nil {
		return err
	}

	m.logger.Info("Tailscale connected")
	return nil
}

// isEmptyStderrError returns true when the error is a command failure with
// no meaningful stderr output (e.g. "command failed: exit status 1 (stderr: )").
func isEmptyStderrError(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "(stderr: )")
}

// connectNetBird connects using the NetBird CLI
func (m *Manager) connectNetBird(config *types.VPNConfig) error {
	m.logger.Info("Connecting to NetBird")

	// Switch profile if specified (for multi-account support).
	// Mirrors the Tailscale flow: select the profile before "up" so the
	// daemon uses the right account. A failed select is fatal: a bare "up"
	// would connect whatever profile was last active — silently the wrong
	// account. NetBird profiles are per-OS-user, and net runs as root, so
	// the profile must have been created for root (sudo netbird profile add).
	if config.Profile != "" {
		m.logger.Debug("Switching NetBird profile", "profile", config.Profile)
		_, err := m.executor.ExecuteWithTimeout(10*time.Second, "netbird", "profile", "select", config.Profile)
		if err != nil {
			return fmt.Errorf("failed to switch NetBird profile %q: %w (check 'sudo netbird profile list' — profiles are per-user and net runs as root)", config.Profile, err)
		}
	}

	// Profile is applied via "profile select" above, so it is intentionally
	// omitted from "up" here.
	args := []string{"up"}

	if config.SetupKey != "" {
		// Pass the setup key via --setup-key-file (a 0600 file) rather than as
		// an argv token so it isn't exposed through `ps` / process inspection.
		keyPath, cleanup, err := m.writeSecretFile("netbird-setupkey", config.SetupKey)
		if err != nil {
			return fmt.Errorf("failed to stage NetBird setup key: %w", err)
		}
		defer cleanup()
		args = append(args, "--setup-key-file", keyPath)
	}
	if config.ManagementURL != "" {
		args = append(args, "--management-url", config.ManagementURL)
	}

	// Always disable DNS (netop manages resolv.conf)
	args = append(args, "--disable-dns")

	_, err := m.executor.ExecuteWithTimeout(30*time.Second, "netbird", args...)
	if err != nil {
		return fmt.Errorf("failed to connect NetBird: %w", err)
	}

	// Verify the tunnel actually came up before reporting success
	if err := m.waitForVPNStatus("netbird", []string{"status", "--json"}, netBirdStatusConnected); err != nil {
		return err
	}

	m.logger.Info("NetBird connected")
	return nil
}

// openVPNDevice extracts the tunnel device name from an OpenVPN config.
// A bare device type ("dev tun" / "dev tap") means the kernel assigns the
// first free unit, which is 0 on a clean system, so those default to
// tun0/tap0 — same as when no dev directive is present.
func openVPNDevice(config string) string {
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "dev" {
			switch fields[1] {
			case "tun":
				return "tun0"
			case "tap":
				return "tap0"
			default:
				return fields[1]
			}
		}
	}
	return "tun0"
}

// connectOpenVPN connects to an OpenVPN server
func (m *Manager) connectOpenVPN(config *types.VPNConfig) error {
	m.logger.Info("Connecting to OpenVPN")

	// Write config to temp file with secure permissions
	tempConfig := filepath.Join(m.runtimeDir, "openvpn.conf")
	err := m.writeFile(tempConfig, config.Config)
	if err != nil {
		return fmt.Errorf("failed to write OpenVPN config: %w", err)
	}
	// Clean up credentials file on all paths (success and failure)
	defer m.removeFile(tempConfig)

	// PID file for tracking this specific OpenVPN process
	pidFile := filepath.Join(m.runtimeDir, "openvpn.pid")

	// Remove any stale pidfile from a crashed run: --writepid is written by
	// the forked daemon, so the liveness check below could otherwise read a
	// dead pid from the previous run and fail a healthy connect.
	m.removeFile(pidFile)

	// Start OpenVPN (10s timeout for daemon startup)
	// Use --writepid to track the specific process we started
	_, err = m.executor.ExecuteWithTimeout(10*time.Second, "openvpn",
		"--config", tempConfig, "--daemon", "--writepid", pidFile)
	if err != nil {
		return fmt.Errorf("failed to start OpenVPN: %w", err)
	}

	// Wait for the tunnel interface from the config to appear (up to 30s)
	device := openVPNDevice(config.Config)
	m.logger.Debug("Waiting for OpenVPN tunnel to establish", "device", device)
	for i := 0; i < 30; i++ {
		// A stale tunnel interface from a previous run can satisfy the device
		// check even though our daemon already died. Confirm the process we
		// started is still alive before reporting success.
		pid, pidErr := m.executor.ExecuteWithTimeout(1*time.Second, "cat", pidFile)
		pid = strings.TrimSpace(pid)
		if pidErr == nil && pid != "" {
			if _, aliveErr := m.executor.ExecuteWithTimeout(1*time.Second, "kill", "-0", pid); aliveErr != nil {
				system.KillProcessByPID(m.executor, m.logger, pidFile)
				return fmt.Errorf("openvpn process exited before the tunnel came up")
			}
		}
		if exists, _ := m.linkMgr.Exists(device); exists {
			m.logger.Info("OpenVPN tunnel established", "device", device)
			return nil
		}
		time.Sleep(time.Second)
	}
	// Clean up on failure
	system.KillProcessByPID(m.executor, m.logger, pidFile)
	return fmt.Errorf("openvpn failed to establish tunnel within 30s")
}

// connectWireGuard connects to a WireGuard VPN. origGW/origIface are the
// default gateway snapshot taken by Connect before any routing changes; they
// are passed in rather than re-queried so the endpoint route and the saved
// restore state can never diverge.
func (m *Manager) connectWireGuard(config *types.VPNConfig, origGW, origIface string) error {
	m.logger.Info("Connecting to WireGuard VPN")

	// Default interface name if not specified
	iface := config.Interface
	if iface == "" {
		iface = "wg0"
	}

	// Write config to temp file with secure permissions
	tempConfig := filepath.Join(m.runtimeDir, "wg.conf")
	err := m.writeFile(tempConfig, config.Config)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config: %w", err)
	}
	// Clean up credentials file on all paths (success and failure)
	defer m.removeFile(tempConfig)

	// Create WireGuard interface — if it already exists, delete and recreate
	// to ensure clean state (no stale routes/config from previous connection)
	err = m.linkMgr.AddWireGuard(iface)
	if err != nil {
		m.logger.Debug("WireGuard interface exists, recreating for clean state", "interface", iface)
		m.linkMgr.Delete(iface)
		err = m.linkMgr.AddWireGuard(iface)
		if err != nil {
			return fmt.Errorf("failed to create WireGuard interface: %w", err)
		}
	}

	// Set config
	_, err = m.executor.ExecuteWithTimeout(5*time.Second, "wg", "setconf", iface, tempConfig)
	if err != nil {
		return fmt.Errorf("failed to set WireGuard config: %w", err)
	}

	// Set IP address if specified (use replace to handle existing addresses)
	if config.Address != "" {
		err = m.addrMgr.Replace(iface, config.Address)
		if err != nil {
			// Clean up interface on failure
			m.linkMgr.Delete(iface)
			return fmt.Errorf("failed to set WireGuard IP: %w", err)
		}
	}

	// Bring interface up
	err = m.linkMgr.SetUp(iface)
	if err != nil {
		// Clean up interface on failure
		m.linkMgr.Delete(iface)
		return fmt.Errorf("failed to bring WireGuard interface up: %w", err)
	}

	// Add routes if gateway is enabled
	if config.Gateway {
		// Route the VPN endpoint via the original gateway so the tunnel's own
		// traffic survives the default-route flip below.
		endpoint := m.extractEndpoint(config.Config)
		endpointIP := endpoint
		if endpoint != "" && net.ParseIP(endpoint) == nil {
			// Hostname endpoint — resolve it now, while the physical default
			// route is still in place, so it can be protected like an IP.
			addrs, lookupErr := net.LookupHost(endpoint)
			if lookupErr != nil || len(addrs) == 0 {
				m.logger.Warn("Failed to resolve WireGuard endpoint hostname; tunnel may drop after default route change", "endpoint", endpoint, "error", lookupErr)
				endpointIP = ""
			} else {
				endpointIP = addrs[0]
			}
		}
		if endpointIP != "" && origGW != "" && origIface != "" {
			// Add route to VPN endpoint via original gateway
			m.logger.Debug("Adding route to VPN endpoint", "endpoint", endpointIP, "gateway", origGW, "interface", origIface)
			err = m.routeMgr.ReplaceRoute(origIface, endpointIP, origGW)
			if err != nil {
				m.logger.Warn("Failed to add route to VPN endpoint", "error", err)
			} else {
				// Store endpoint for cleanup on disconnect (already holding m.mu from Connect)
				m.endpointRoute = endpointIP
			}
		}

		// Set default route via WireGuard interface.
		// The original gateway was already saved by Connect() before calling connectWireGuard,
		// so disconnect can restore it. If there was no original gateway, warn but proceed —
		// the user explicitly enabled gateway mode.
		err = m.routeMgr.ReplaceDefault(iface, "", 0)
		if err != nil {
			m.logger.Warn("Failed to set default route", "error", err)
		}
	}

	m.logger.Info("WireGuard VPN connection established", "interface", iface)
	return nil
}

// extractEndpoint extracts the endpoint IP from a WireGuard config
// Supports IPv4 (1.2.3.4:51820), IPv6 ([2001:db8::1]:51820), and hostnames
func (m *Manager) extractEndpoint(config string) string {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "endpoint") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				endpoint := strings.TrimSpace(parts[1])

				// Handle IPv6 format: [2001:db8::1]:51820
				if strings.HasPrefix(endpoint, "[") {
					if idx := strings.Index(endpoint, "]:"); idx != -1 {
						// Return IP without brackets: 2001:db8::1
						return endpoint[1:idx]
					}
					// No port, just brackets: [2001:db8::1]
					return strings.Trim(endpoint, "[]")
				}

				// Handle IPv4:port or hostname:port
				// IPv4 addresses and hostnames use : as port separator
				// Count colons to distinguish from IPv6 without brackets (shouldn't happen but be safe)
				colonCount := strings.Count(endpoint, ":")
				if colonCount == 1 {
					// Single colon means IPv4:port or hostname:port
					if idx := strings.LastIndex(endpoint, ":"); idx != -1 {
						return endpoint[:idx]
					}
				} else if colonCount == 0 {
					// No colon, just hostname or IP without port
					return endpoint
				}
				// Multiple colons without brackets - likely malformed IPv6
				// Return as-is and let the caller handle it
				return endpoint
			}
		}
	}
	return ""
}

// getCurrentGateway returns the current default gateway IP and interface via
// netlink. For a normal LAN default route both are set (e.g. "192.168.1.1",
// "eth0"). For a device-only default route such as `default dev wg0` the
// gateway is "" and only iface is set — callers must handle that case (see
// restoreDefaultRouteFromState). Returns ("", "") if there is no default route
// or netlink is unavailable.
func (m *Manager) getCurrentGateway() (gateway, iface string) {
	route, err := m.routeMgr.GetDefaultRoute()
	if err != nil {
		m.logger.Debug("Failed to get default route", "error", err)
		return "", ""
	}
	return route.Gw, route.Iface
}

// writeFile writes content to a file with secure permissions (0600)
// Uses install command to atomically create file with correct permissions
// avoiding TOCTOU race where file exists briefly with wrong permissions
func (m *Manager) writeFile(path, content string) error {
	return system.WriteSecureFile(path, content)
}

// writeSecretFile writes a credential to a 0600 file named <name> in the
// runtime dir and returns its path plus a cleanup func. Keeping keys in a file
// rather than an argv token prevents exposure via `ps` and process inspection.
func (m *Manager) writeSecretFile(name, secret string) (path string, cleanup func(), err error) {
	path = filepath.Join(m.runtimeDir, name)
	if err := m.writeFile(path, secret); err != nil {
		return "", func() {}, err
	}
	return path, func() { m.removeFile(path) }, nil
}

// activeVPNFilePath returns the path to the active VPN state file
func (m *Manager) activeVPNFilePath() string {
	return filepath.Join(m.runtimeDir, "active-vpn")
}

// setActiveVPNState records the full VPN state to the state file
func (m *Manager) setActiveVPNState(state vpnState) error {
	activeVPNFile := m.activeVPNFilePath()
	// Ensure runtime directory exists
	if err := os.MkdirAll(filepath.Dir(activeVPNFile), 0755); err != nil {
		m.logger.Debug("Failed to create runtime directory", "error", err)
		// Non-fatal: status will fall back to interface detection
		return err
	}
	// Format: vpn-name|interface|type|originalGateway|originalInterface|endpointRoute
	content := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		state.Name, state.Interface, state.Type,
		state.OriginalGateway, state.OriginalInterface, state.EndpointRoute)
	// Use 0600 for consistency with other runtime files (e.g., wg.conf, openvpn.conf)
	return os.WriteFile(activeVPNFile, []byte(content), 0600)
}

// getActiveVPNState reads the full VPN state from the state file
func (m *Manager) getActiveVPNState() *vpnState {
	data, err := os.ReadFile(m.activeVPNFilePath())
	if err != nil {
		return nil
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	// Parse enhanced format: vpn-name|interface|type|originalGateway|originalInterface|endpointRoute
	parts := strings.Split(content, "|")
	state := &vpnState{Name: parts[0]}
	if len(parts) >= 2 {
		state.Interface = parts[1]
	}
	if len(parts) >= 3 {
		state.Type = parts[2]
	}
	if len(parts) >= 4 {
		state.OriginalGateway = parts[3]
	}
	if len(parts) >= 5 {
		state.OriginalInterface = parts[4]
	}
	if len(parts) >= 6 {
		state.EndpointRoute = parts[5]
	}
	return state
}

// clearActiveVPN removes the active VPN state file
func (m *Manager) clearActiveVPN() {
	activeVPNFile := m.activeVPNFilePath()
	if err := os.Remove(activeVPNFile); err != nil && !os.IsNotExist(err) {
		m.logger.Debug("Failed to remove active VPN file", "error", err)
	}
}

// getActiveVPN reads the currently active VPN name from the state file
func (m *Manager) getActiveVPN() string {
	state := m.getActiveVPNState()
	if state == nil {
		return ""
	}
	return state.Name
}
