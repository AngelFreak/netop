package network

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/netlink"
	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// wiredSettleDelay is how long we wait after `ip link set up` before starting
// DHCP on a wired interface. USB ethernet adapters (ASIX, RTL8153, etc.)
// often report carrier=1 before they can reliably forward L2 frames; the
// first 1-2s of TX after link-up gets dropped. Exposed as a var so tests
// can shrink it without affecting production behavior.
var wiredSettleDelay = 1500 * time.Millisecond

// Manager implements the NetworkManager interface
type Manager struct {
	executor         types.SystemExecutor
	logger           types.Logger
	dhcpClient       types.DHCPClientManager
	routeMgr         types.RouteManager // netlink-backed routing table access
	addrMgr          types.AddrManager  // netlink-backed interface address access
	linkMgr          types.LinkManager  // netlink-backed link access (up/down, MAC)
	dnsOwnershipPath string             // overridable for tests; defaults to types.RuntimeDir/dns-owned
	resolvConfPath   string             // overridable for tests; defaults to /etc/resolv.conf
	// setImmutable sets/clears the immutable flag on a file. Defaults to
	// system.SetImmutable (native FS_IOC_SETFLAGS ioctl); overridable in tests
	// so lock/unlock intent can be observed without CAP_LINUX_IMMUTABLE.
	setImmutable func(path string, immutable bool) error
}

// NewManager creates a new network manager
func NewManager(executor types.SystemExecutor, logger types.Logger, dhcpClient types.DHCPClientManager) *Manager {
	return &Manager{
		executor:         executor,
		logger:           logger,
		dhcpClient:       dhcpClient,
		routeMgr:         netlink.NewRouteManager(),
		addrMgr:          netlink.NewAddrManager(),
		linkMgr:          netlink.NewLinkManager(),
		dnsOwnershipPath: types.RuntimeDir + "/dns-owned",
		resolvConfPath:   "/etc/resolv.conf",
		setImmutable:     system.SetImmutable,
	}
}

// resolvConf returns the resolv.conf path (overridable in tests).
func (m *Manager) resolvConf() string {
	if m.resolvConfPath != "" {
		return m.resolvConfPath
	}
	return "/etc/resolv.conf"
}

// immutable applies the immutable flag via the injected setter (defaults to
// system.SetImmutable), tolerating a nil setter for zero-value Managers built
// in tests.
func (m *Manager) immutable(path string, immutable bool) error {
	if m.setImmutable == nil {
		return system.SetImmutable(path, immutable)
	}
	return m.setImmutable(path, immutable)
}

// lockResolvConf sets the immutable flag on resolv.conf natively (replacing
// `chattr +i`), preventing external tools (dhclient, netbird) from overwriting
// DNS that netop configured.
func (m *Manager) lockResolvConf() error {
	return m.immutable(m.resolvConf(), true)
}

// killProcess kills processes matching a pattern with SIGKILL (fast, no graceful shutdown)
func (m *Manager) killProcess(pattern string) {
	system.KillProcessFast(m.executor, m.logger, pattern)
}

// dnsOwnedPath returns the marker file indicating netop owns /etc/resolv.conf.
// When present, ClearDNS will clear resolv.conf on disconnect; when absent
// (DNS came from DHCP and we never locked it), ClearDNS is a no-op so we
// don't nuke DNS that was there before netop started.
func (m *Manager) dnsOwnedPath() string {
	if m.dnsOwnershipPath != "" {
		return m.dnsOwnershipPath
	}
	return types.RuntimeDir + "/dns-owned"
}

func (m *Manager) markDNSOwned() {
	path := m.dnsOwnedPath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		m.logger.Debug("Failed to mark DNS ownership", "error", err)
	}
}

func (m *Manager) clearDNSOwnership() {
	_ = os.Remove(m.dnsOwnedPath())
}

func (m *Manager) isDNSOwned() bool {
	_, err := os.Stat(m.dnsOwnedPath())
	return err == nil
}

// SetDNS configures DNS servers
func (m *Manager) SetDNS(servers []string) error {
	if len(servers) == 0 || (len(servers) == 1 && servers[0] == "dhcp") {
		// Remove immutable flag to allow DHCP to update DNS
		if err := m.unlockResolvConf(); err != nil {
			m.logger.Debug("Failed to remove immutable flag (may not be set)", "error", err)
		}
		m.clearDNSOwnership()
		m.logger.Info("Using DHCP for DNS configuration")
		return nil
	}

	m.logger.Info("Setting DNS servers", "servers", servers)

	// Write to /etc/resolv.conf
	var resolvConf strings.Builder
	var validCount int
	for _, server := range servers {
		if net.ParseIP(server) != nil {
			resolvConf.WriteString(fmt.Sprintf("nameserver %s\n", server))
			validCount++
		} else {
			m.logger.Warn("Skipping invalid DNS server (not a valid IP)", "server", server)
		}
	}

	if validCount == 0 {
		return fmt.Errorf("no valid DNS servers: none of %v are valid IP addresses", servers)
	}

	if err := m.unlockResolvConf(); err != nil {
		m.logger.Warn("Failed to unlock resolv.conf", "error", err)
	}

	err := m.writeFileDirect(m.resolvConf(), resolvConf.String())
	if err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	// Lock to prevent other tools (dhclient, netbird) from overwriting
	if err := m.lockResolvConf(); err != nil {
		m.logger.Warn("Failed to lock resolv.conf", "error", err)
	}
	m.markDNSOwned()

	return nil
}

// ClearDNS clears /etc/resolv.conf, but only if netop wrote it. If DNS was
// provided by DHCP and never locked by us, we leave it alone so `net stop`
// doesn't wipe out DNS that the user had before netop ran.
func (m *Manager) ClearDNS() error {
	cleared, err := m.clearDNS()
	if err != nil {
		return err
	}
	if !cleared {
		m.logger.Debug("DNS not owned by netop, leaving resolv.conf alone")
	}
	return nil
}

// ClearDNSIfOwned clears resolv.conf only if netop set it, returning whether
// anything was actually changed. Used by `net stop` to avoid printing a
// misleading "DNS cleared" line when netop never owned DNS in the first place.
func (m *Manager) ClearDNSIfOwned() (bool, error) {
	return m.clearDNS()
}

func (m *Manager) clearDNS() (bool, error) {
	m.logger.Debug("Clearing DNS configuration")

	if !m.isDNSOwned() {
		return false, nil
	}

	if err := m.unlockResolvConf(); err != nil {
		m.logger.Warn("Failed to unlock resolv.conf", "error", err)
	}

	if err := m.writeFileDirect(m.resolvConf(), "# DNS cleared by net\n"); err != nil {
		return false, fmt.Errorf("failed to clear resolv.conf: %w", err)
	}
	m.clearDNSOwnership()

	m.logger.Debug("DNS configuration cleared")
	return true, nil
}

// LockDNS sets the immutable flag on /etc/resolv.conf to prevent external
// tools (like netbird) from overwriting DNS configuration.
func (m *Manager) LockDNS() {
	if err := m.lockResolvConf(); err != nil {
		m.logger.Warn("Failed to lock resolv.conf", "error", err)
	}
	m.markDNSOwned()
}

// unlockResolvConf removes the immutable flag from /etc/resolv.conf natively
// (replacing `chattr -i`). VPN clients like netbird set this flag and may leave
// it after disconnecting, which prevents DHCP or net from updating DNS.
func (m *Manager) unlockResolvConf() error {
	return m.immutable(m.resolvConf(), false)
}

// resolvConfHasNameserver reports whether /etc/resolv.conf currently contains
// at least one active "nameserver" line (ignoring comments/blank lines).
func (m *Manager) resolvConfHasNameserver() bool {
	output, err := os.ReadFile(m.resolvConf())
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nameserver ") {
			return true
		}
	}
	return false
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
	if err := m.linkMgr.SetDown(iface); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	// Set MAC address
	if err := m.linkMgr.SetMAC(iface, mac); err != nil {
		return fmt.Errorf("failed to set MAC address: %w", err)
	}

	// Bring interface up
	if err := m.linkMgr.SetUp(iface); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// GetMAC gets the current MAC address
func (m *Manager) GetMAC(iface string) (string, error) {
	mac, err := m.linkMgr.GetMAC(iface)
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w", err)
	}
	if mac == "" {
		return "", fmt.Errorf("MAC address not found in interface output")
	}
	return mac, nil
}

// SetIP sets IP address and gateway. If metric > 0, it is applied to the default
// route; otherwise the kernel default is used.
func (m *Manager) SetIP(iface, addr, gateway string, metric int) error {
	m.logger.Info("Setting IP configuration", "interface", iface, "addr", addr, "gateway", gateway, "metric", metric)
	m.logger.Debug("SetIP using wireless interface", "interface", iface)

	// Validate interface name
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	// Flush existing addresses
	if err := m.addrMgr.Flush(iface); err != nil {
		m.logger.Warn("Failed to flush addresses", "error", err)
	}

	if addr != "" {
		// Validate CIDR notation (e.g., "10.0.0.1/24")
		if !strings.Contains(addr, "/") {
			return fmt.Errorf("invalid IP address %q: must be in CIDR notation (e.g., 10.0.0.1/24)", addr)
		}
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid IP address %q: %w", addr, err)
		}
		if ip == nil {
			return fmt.Errorf("invalid IP address %q", addr)
		}

		// Add IP address
		if err := m.addrMgr.Add(iface, addr); err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	if gateway != "" {
		// Validate gateway is a valid IP
		if net.ParseIP(gateway) == nil {
			return fmt.Errorf("invalid gateway %q: must be a valid IP address", gateway)
		}

		// Install the default route with metric when set so multiple links
		// coexist deterministically (lower metric wins). SetDefaultForIface
		// replaces only THIS interface's default route, leaving other
		// interfaces' defaults intact — preserving multi-homing.
		if err := m.routeMgr.SetDefaultForIface(iface, gateway, metric); err != nil {
			return fmt.Errorf("failed to set gateway: %w", err)
		}
	}

	return nil
}

// AddRoute adds a custom route
func (m *Manager) AddRoute(iface, destination, gateway string) error {
	m.logger.Info("Adding route", "destination", destination, "gateway", gateway, "interface", iface)

	return m.routeMgr.AddRoute(iface, destination, gateway)
}

// FlushRoutes removes all routes
func (m *Manager) FlushRoutes(iface string) error {
	m.logger.Info("Flushing routes", "interface", iface)

	return m.routeMgr.FlushRoutes(iface)
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
	hostsBytes, err := os.ReadFile("/etc/hosts")
	if err != nil {
		m.logger.Warn("Failed to read /etc/hosts", "error", err)
	} else {
		// Check if we need to update the localhost entry
		lines := strings.Split(string(hostsBytes), "\n")
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
		if err = os.WriteFile("/etc/hosts", []byte(newHostsContent), 0644); err != nil {
			m.logger.Warn("Failed to update /etc/hosts", "error", err)
		} else {
			m.logger.Debug("Updated /etc/hosts with new hostname")
		}
	}

	// Now set the hostname (after /etc/hosts is updated)
	if err = setHostname(hostname); err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}

	// Also update /etc/hostname for persistence
	if err = os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
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
	// The DHCP client can't write DNS to an immutable resolv.conf. If netop
	// (or a VPN client) locked it, unlock and release ownership first so the
	// renewed lease's nameservers actually take effect.
	if err := m.unlockResolvConf(); err != nil {
		m.logger.Debug("Failed to unlock resolv.conf before DHCP renew (may not be locked)", "error", err)
	}
	m.clearDNSOwnership()
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
			if hasCarrier(candidate) {
				m.logger.Info("Detected wired interface with carrier", "interface", candidate)
				return candidate
			}
		}
		// No interface with carrier found, try bringing them up and polling for carrier
		m.logger.Debug("No interface with carrier found, trying to bring interfaces up")
		for _, candidate := range candidates {
			// Bring interface up
			err := m.linkMgr.SetUp(candidate)
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
	isFirstOctet := true
	for strings.Contains(result, "??") {
		randomByte := make([]byte, 1)
		_, err := rand.Read(randomByte)
		if err != nil {
			randomByte[0] = 0x00 // Fallback
		}
		if isFirstOctet && strings.Index(result, "??") < 3 {
			// First octet: set locally-administered bit, clear multicast bit
			randomByte[0] = (randomByte[0] | 0x02) & 0xfe
		}
		result = strings.Replace(result, "??", fmt.Sprintf("%02x", randomByte[0]), 1)
		isFirstOctet = false
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
	parts := strings.SplitN(output, ": ", 2)
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

// writeFileDirect writes content to path with 0644 permissions, preserving a
// symlink at path by writing through to its target. Native replacement for
// shelling out to `tee`, which also followed symlinks.
//
// /etc/resolv.conf is frequently a symlink (e.g. -> /run/systemd/resolve/
// stub-resolv.conf on systemd-resolved) or a bind-mount (containers). A plain
// temp-file+rename over path would replace the symlink with a regular file
// (breaking resolved's management) or fail with EBUSY on a bind-mount. So we
// resolve path to its real target and write there: atomically via temp+rename
// when the target directory is writable (never half-written), otherwise
// in-place through the existing file descriptor as a fallback.
func (m *Manager) writeFileDirect(path, content string) error {
	// Resolve symlinks so we write through to the real file, not over the link.
	// EvalSymlinks fails if path itself doesn't exist yet; fall back to path.
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}

	if err := atomicWrite(target, content); err != nil {
		// Atomic rename can fail when the target's directory isn't writable or
		// the target is a bind-mount (EBUSY / cross-device). Fall back to
		// truncating and writing the existing file in place, which follows the
		// symlink/bind-mount the same way `tee` did.
		if writeErr := os.WriteFile(target, []byte(content), 0644); writeErr != nil {
			return fmt.Errorf("writing %q: atomic rename failed (%v); in-place write failed: %w", target, err, writeErr)
		}
	}
	return nil
}

// atomicWrite writes content to path via a temp file in the same directory
// followed by a rename, so the file never appears half-written. The temp file
// must be in the same directory as path for the rename to stay on one
// filesystem.
func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".net-resolv-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming temp file to %q: %w", path, err)
	}
	tmpName = ""
	return nil
}

// waitForCarrier polls for carrier detection on an interface
// Returns true if carrier is detected within the timeout, false otherwise
func (m *Manager) waitForCarrier(iface string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	pollInterval := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		if hasCarrier(iface) {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

// hasCarrier reports whether the interface currently has a physical link, by
// reading /sys/class/net/<iface>/carrier (native replacement for
// `cat .../carrier`). A missing or unreadable file (e.g. iface down) reads as
// no carrier.
func hasCarrier(iface string) bool {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/carrier")
	return err == nil && strings.TrimSpace(string(b)) == "1"
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
		m.logger.Debug("Clearing resolv.conf for DHCP DNS")
		if err := m.unlockResolvConf(); err != nil {
			m.logger.Warn("Failed to unlock resolv.conf, DHCP may not be able to set DNS", "error", err)
		}
		// Clear stale DNS entries so DHCP client can write fresh ones.
		// Without this, resolv.conf may retain DNS from a previous connection
		// (set via SetDNS with chattr +i), or from a VPN client like netbird.
		if err := m.writeFileDirect(m.resolvConf(), "# Waiting for DHCP\n"); err != nil {
			m.logger.Warn("Failed to clear resolv.conf", "error", err)
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
		// WiFi DHCP installs a default route without a metric; re-add with metric
		// so a concurrently-connected wired interface (lower metric) takes priority.
		m.applyDefaultRouteMetric(config.Interface, config.DefaultRouteMetric())
	} else {
		m.logger.Debug("No SSID specified in network config - treating as wired connection")

		// Tear down any active WiFi connection first so its default route,
		// DHCP client, and wpa_supplicant don't interfere with the wired link.
		if wifiMgr != nil {
			m.logger.Debug("Disconnecting WiFi before switching to wired")
			if err := wifiMgr.Disconnect(); err != nil {
				m.logger.Debug("No active WiFi to disconnect", "error", err)
			}
		}

		// For wired connections, bring up the interface and get DHCP if no static IP
		if config.Interface != "" {
			// Flush stale IP addresses and routes — after suspend/resume the old
			// network state remains on the interface even though the link was
			// down. `route flush dev <iface>` already drops any default route
			// bound to this interface, so we don't need a separate global
			// `route del default` (which would silently delete a VPN's default
			// route — e.g. a `gateway: true` WireGuard tunnel — when the user
			// reconnects wired).
			m.addrMgr.Flush(config.Interface)
			m.routeMgr.FlushRoutes(config.Interface)

			m.logger.Info("Bringing up wired interface", "interface", config.Interface)
			err := m.linkMgr.SetUp(config.Interface)
			if err != nil {
				m.logger.Warn("Failed to bring up wired interface", "interface", config.Interface, "error", err)
			}

			// Wait for link carrier before starting DHCP (poll up to 5 seconds)
			if !m.waitForCarrier(config.Interface, 5*time.Second) {
				m.logger.Warn("No carrier detected on interface, proceeding anyway", "interface", config.Interface)
			}

			// USB ethernet adapters frequently report carrier=1 before they
			// can reliably forward L2 frames; sleeping briefly avoids losing
			// the first DHCP DISCOVER. See wiredSettleDelay docs.
			time.Sleep(wiredSettleDelay)

			if config.Addr == "" {
				m.logger.Info("Obtaining DHCP lease on wired interface", "interface", config.Interface)
				err := m.StartDHCP(config.Interface, config.Hostname)
				if err != nil {
					// Surface the failure instead of reporting a successful
					// connection with no lease. The WiFi path already errors
					// out on DHCP failure; wired should be consistent.
					return fmt.Errorf("failed to obtain DHCP lease on %s: %w", config.Interface, err)
				}
				m.applyDefaultRouteMetric(config.Interface, config.DefaultRouteMetric())
			}
		}
	}

	// Set static IP if configured
	if config.Addr != "" {
		m.logger.Debug("Setting static IP from config", "addr", config.Addr, "gateway", config.Gateway)
		err := m.SetIP(config.Interface, config.Addr, config.Gateway, config.DefaultRouteMetric())
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

	// Lock resolv.conf after DHCP-provided DNS is written.
	// External tools like netbird actively rewrite resolv.conf with their own
	// DNS servers. If netbird is still connected when switching WiFi, it will
	// overwrite the DHCP-provided DNS, breaking internet connectivity.
	// Custom DNS is already locked by SetDNS(), so only lock here for DHCP DNS.
	//
	// Only lock if DHCP actually wrote nameservers — a static-addr network with
	// dns: dhcp never runs a DHCP client, so resolv.conf still holds only the
	// "# Waiting for DHCP" placeholder; locking that would strand the system
	// with zero nameservers and an immutable file.
	if useDHCPForDNS {
		if m.resolvConfHasNameserver() {
			// LockDNS marks ownership so ClearDNS/net stop can later unlock it.
			// A raw chattr +i here would leave resolv.conf immutable forever.
			m.LockDNS()
			m.logger.Debug("Locked resolv.conf to prevent external DNS overwrite")
		} else {
			m.logger.Debug("Skipping resolv.conf lock: no nameserver written (no DHCP client ran)")
		}
	}

	return nil
}

// GetConnectionInfo retrieves connection information for the specified interface
func (m *Manager) GetConnectionInfo(iface string) (*types.Connection, error) {
	m.logger.Debug("Getting connection info", "interface", iface)

	// Get IP address (netlink).
	ip, err := m.addrMgr.GetFirstIPv4(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses: %w", err)
	}

	// Get gateway from the interface's default route (netlink).
	var gateway net.IP
	if route, rerr := m.routeMgr.GetDefaultRouteForIface(iface); rerr != nil {
		m.logger.Debug("Failed to get default route", "iface", iface, "error", rerr)
	} else if route.Gw != "" {
		gateway = net.ParseIP(route.Gw)
	}

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
		SSID:      m.currentSSID(iface),
	}, nil
}

// currentSSID returns the SSID the interface is associated with, or "" for
// wired interfaces / when not associated. Uses `iw dev <iface> link`, which
// prints "SSID: <name>" when connected.
func (m *Manager) currentSSID(iface string) string {
	output, err := m.executor.ExecuteWithTimeout(2*time.Second, "iw", "dev", iface, "link")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSID: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "SSID: "))
		}
	}
	return ""
}

// applyDefaultRouteMetric finds the DHCP-installed default route on iface and
// re-adds it with the given metric. DHCP clients (udhcpc/dhclient) install
// default routes without metrics, so when two interfaces are up simultaneously
// the kernel picks by insertion order instead of a deterministic priority.
// This re-installs with metric so wired wins over WiFi (or vice versa per config).
func (m *Manager) applyDefaultRouteMetric(iface string, metric int) {
	if metric <= 0 {
		return
	}
	route, err := m.routeMgr.GetDefaultRouteForIface(iface)
	if err != nil {
		// No default route on this interface yet (or netlink error) — nothing
		// to re-tag with a metric.
		return
	}
	if route.Gw == "" {
		m.logger.Debug("No gateway in default route, skipping metric", "iface", iface)
		return
	}
	// Skip if the metric is already set to the desired value — avoid churn.
	if route.Metric == metric {
		return
	}
	m.logger.Debug("Applying default route metric", "iface", iface, "gateway", route.Gw, "metric", metric)
	if err := m.routeMgr.SetDefaultForIface(iface, route.Gw, metric); err != nil {
		m.logger.Warn("Failed to reinstall default route with metric", "iface", iface, "error", err)
	}
}

// Disconnect releases DHCP, flushes addresses and routes, and brings the link
// down for a single interface. Safe to call on interfaces that are already
// down or have no configuration.
func (m *Manager) Disconnect(iface string) error {
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}
	m.logger.Info("Disconnecting interface", "interface", iface)

	if m.dhcpClient != nil {
		_ = m.dhcpClient.Release(iface)
	}
	m.addrMgr.Flush(iface)
	m.routeMgr.FlushRoutes(iface)
	if err := m.linkMgr.SetDown(iface); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}
	return nil
}

// DisconnectAll tears down every physical interface (wired or wireless) that
// currently has an IPv4 address. Virtual interfaces (lo, docker*, veth*, br*,
// wg*, tun*, tailscale*) are skipped. Returns the list of interfaces torn down.
func (m *Manager) DisconnectAll() []string {
	var torn []string
	ifaces, err := net.Interfaces()
	if err != nil {
		m.logger.Debug("Failed to list interfaces", "error", err)
		return torn
	}
	for _, iface := range ifaces {
		name := iface.Name
		if name == "lo" || strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br") ||
			strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") ||
			strings.HasPrefix(name, "tailscale") || strings.HasPrefix(name, "virbr") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLinkLocalUnicast() {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}
		if err := m.Disconnect(name); err != nil {
			m.logger.Warn("Failed to disconnect interface", "interface", name, "error", err)
			continue
		}
		torn = append(torn, name)
	}
	return torn
}

// getDNSServers reads DNS servers from resolv.conf
func (m *Manager) getDNSServers() ([]net.IP, error) {
	output, err := os.ReadFile(m.resolvConf())
	if err != nil {
		return nil, err
	}
	return system.ParseDNSFromResolvConf(string(output)), nil
}
