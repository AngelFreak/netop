// Package dhcpclient provides DHCP client functionality for obtaining network leases.
// This is distinct from pkg/dhcp which handles DHCP server operations for hotspot mode.
package dhcpclient

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/angelfreak/net/pkg/system"
	"github.com/angelfreak/net/pkg/types"
)

// Timeout constants for DHCP operations
const (
	// UdhcpcDiscoverRetries is the number of DHCP DISCOVER packets udhcpc sends
	// before giving up. Default in BusyBox is 3; we raise to 6 so the total
	// discovery window matches NetworkManager's behavior more closely. This is
	// critical for USB ethernet adapters that take 1-3s to start passing frames
	// after `ip link up`, even though /sys/class/net/X/carrier already reads 1.
	UdhcpcDiscoverRetries = 6

	// UdhcpcDiscoverTimeout is the seconds between each DISCOVER retry.
	// 3s is BusyBox's default; total discover window = retries * timeout = 18s.
	UdhcpcDiscoverTimeout = 3

	// UdhcpcTryAgain is the seconds to wait before re-trying after a full
	// discover cycle. Only relevant when not using -n; included for documentation.
	UdhcpcTryAgain = 10

	// UdhcpcTimeout is the wall-clock timeout for the udhcpc process.
	// Must exceed UdhcpcDiscoverRetries * UdhcpcDiscoverTimeout (= 18s) plus
	// time for ARP probing, route setup, and script hooks.
	UdhcpcTimeout = 30 * time.Second

	// DhclientTimeout is the timeout for dhclient. Increased from 15s to 60s
	// to match dhclient's RFC-2131-compliant default timeout, which gives
	// flaky links (USB ethernet, slow switches) time to negotiate.
	DhclientTimeout = 60 * time.Second

	// CleanupTimeout is the timeout for cleanup operations (pkill, rm)
	CleanupTimeout = 500 * time.Millisecond

	// IPCheckTimeout is the timeout for checking acquired IP address
	IPCheckTimeout = 2 * time.Second

	// RetryDelay is how long to wait between DHCP attempts. Mirrors
	// NetworkManager's autoconnect-retry behavior.
	RetryDelay = 2 * time.Second

	// UdhcpcScriptDir holds net's udhcpc event script. Not /run/net: /run
	// is mounted noexec on many distros, and udhcpc execs the script.
	UdhcpcScriptDir = "/var/lib/net"

	// DhclientEnterHooksDir is where Debian's dhclient-script sources
	// enter hooks from (via run-parts, so names must match [A-Za-z0-9_-]).
	DhclientEnterHooksDir = "/etc/dhcp/dhclient-enter-hooks.d"
	DhclientEnterHookName = "net-dns-owned"
)

// Manager implements the DHCPClientManager interface
type Manager struct {
	executor    types.SystemExecutor
	logger      types.Logger
	dhcpTimeout time.Duration // Configurable overall DHCP timeout (0 = use defaults)
	runtimeDir  string        // overridable for tests; defaults to types.RuntimeDir
	scriptDir   string        // overridable for tests; defaults to UdhcpcScriptDir
	hooksDir    string        // overridable for tests; defaults to DhclientEnterHooksDir
}

// NewManager creates a new DHCP client manager
func NewManager(executor types.SystemExecutor, logger types.Logger) *Manager {
	return &Manager{
		executor:   executor,
		logger:     logger,
		runtimeDir: types.RuntimeDir,
	}
}

// runDir returns the runtime directory for dhclient/udhcpc files (overridable
// in tests).
func (m *Manager) runDir() string {
	if m.runtimeDir != "" {
		return m.runtimeDir
	}
	return types.RuntimeDir
}

// SetDHCPTimeout configures the DHCP acquisition timeout from user config.
// If set, overrides the default UdhcpcTimeout and DhclientTimeout constants.
func (m *Manager) SetDHCPTimeout(timeout time.Duration) {
	if timeout > 0 {
		m.dhcpTimeout = timeout
	}
}

// getUdhcpcTimeout returns the configured timeout or the default
func (m *Manager) getUdhcpcTimeout() time.Duration {
	if m.dhcpTimeout > 0 {
		return m.dhcpTimeout
	}
	return UdhcpcTimeout
}

// getDhclientTimeout returns the configured timeout or the default
func (m *Manager) getDhclientTimeout() time.Duration {
	if m.dhcpTimeout > 0 {
		return m.dhcpTimeout
	}
	return DhclientTimeout
}

// Acquire obtains a DHCP lease for the interface.
// hostname is optional - if provided, it will be sent in DHCP requests without changing system hostname.
//
// Client selection: wired interfaces prefer dhclient (RFC-2131 backoff, longer
// default timeout) because USB ethernet adapters often need a longer discovery
// window than udhcpc's default. WiFi interfaces prefer udhcpc (faster on the
// already-associated link). If the preferred client isn't installed, falls
// back to whichever is available.
//
// Each attempt is retried once on failure with a short delay, mirroring
// NetworkManager's autoconnect-retries default.
func (m *Manager) Acquire(iface string, hostname string) error {
	// Validate interface name to prevent command injection
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	// Validate hostname if provided
	if hostname != "" {
		if err := types.ValidateHostname(hostname); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	m.logger.Info("Acquiring DHCP lease", "interface", iface)

	hasUdhcpc := m.executor.HasCommand("udhcpc")
	hasDhclient := m.executor.HasCommand("dhclient")

	// Wired interfaces prefer dhclient — its default 60s timeout and RFC-2131
	// exponential backoff handle slow USB ethernet adapters and flaky switches
	// far better than udhcpc's 3-retry default. WiFi interfaces prefer udhcpc
	// (faster on already-associated links). dhclient remains the historical
	// fallback when udhcpc is unavailable.
	var attempt func() error
	switch {
	case isWiredInterface(iface) && hasDhclient:
		m.logger.Debug("Using dhclient for DHCP on wired interface", "interface", iface)
		attempt = func() error { return m.acquireDhclient(iface, hostname) }
	case hasUdhcpc:
		m.logger.Debug("Using udhcpc for DHCP", "interface", iface)
		attempt = func() error { return m.acquireUdhcpc(iface, hostname) }
	case hasDhclient:
		m.logger.Debug("Using dhclient for DHCP", "interface", iface)
		attempt = func() error { return m.acquireDhclient(iface, hostname) }
	default:
		return fmt.Errorf("no DHCP client found: install udhcpc (recommended) or dhclient")
	}

	if err := attempt(); err == nil {
		return nil
	} else {
		m.logger.Warn("DHCP attempt failed, retrying once", "interface", iface, "error", err)
		time.Sleep(RetryDelay)
		if retryErr := attempt(); retryErr != nil {
			return retryErr
		}
		return nil
	}
}

// isWiredInterface returns true if the interface name matches a wired prefix.
// Mirrors the detection logic in pkg/network/network.go: eth, enp, enx (USB
// MAC-based), eno (onboard), ens (slot-based), em (Dell/BSD-style), usb.
func isWiredInterface(iface string) bool {
	for _, prefix := range []string{"eth", "enp", "enx", "eno", "ens", "em", "usb"} {
		if strings.HasPrefix(iface, prefix) {
			return true
		}
	}
	return false
}

// Release stops any running DHCP client for the interface and cleans up lease files.
// This is a best-effort cleanup operation - errors are logged but not returned
// since partial cleanup is acceptable for network operations.
func (m *Manager) Release(iface string) error {
	// Validate interface name
	if err := types.ValidateInterfaceName(iface); err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	m.logger.Debug("Releasing DHCP lease", "interface", iface)

	var errs []string

	// Escape regex special characters in interface name (e.g., eth-0 has '-' which is a regex char)
	escapedIface := regexp.QuoteMeta(iface)

	// Prefer graceful shutdown via pidfile: SIGTERM lets udhcpc send a
	// DHCPRELEASE (via -R) and clean up the lease on the server side. Fall
	// back to pkill -9 if pidfile is missing or the process is already dead.
	pidFile := m.udhcpcPidFile(iface)
	if data, err := os.ReadFile(pidFile); err == nil {
		pid := strings.TrimSpace(string(data))
		if n, convErr := strconv.Atoi(pid); convErr == nil && n > 0 {
			if err := syscall.Kill(n, syscall.SIGTERM); err != nil {
				m.logger.Debug("Failed to SIGTERM udhcpc via pidfile", "pid", pid, "error", err)
			}
		}
		_ = os.Remove(pidFile)
	}

	// Backstop: kill any udhcpc/dhclient still matching the interface. This
	// catches daemons started outside of netop or leftover processes from a
	// crashed run.
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "udhcpc.*"+escapedIface); err != nil {
		m.logger.Debug("No udhcpc process to kill", "interface", iface)
	}
	if _, err := m.executor.ExecuteWithTimeout(CleanupTimeout, "pkill", "-9", "-f", "dhclient.*"+escapedIface); err != nil {
		m.logger.Debug("No dhclient process to kill", "interface", iface)
	}

	// Clean up lease files
	leaseFiles := []string{
		"/var/lib/dhcp/dhclient." + iface + ".leases",
		m.runDir() + "/dhclient." + iface + ".leases",
	}
	for _, f := range leaseFiles {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("failed to remove %s: %v", f, err))
		}
	}

	// Clean up interface-specific dhclient config
	confFile := m.runDir() + "/dhclient." + iface + ".conf"
	if err := os.Remove(confFile); err != nil && !os.IsNotExist(err) {
		m.logger.Debug("Failed to remove dhclient config", "file", confFile, "error", err)
	}

	if len(errs) > 0 {
		m.logger.Debug("Some cleanup operations failed", "errors", strings.Join(errs, "; "))
	}

	return nil
}

// Renew renews the DHCP lease for the interface.
// For simplicity, this performs a fresh acquisition (same behavior as original implementation).
func (m *Manager) Renew(iface string, hostname string) error {
	m.logger.Info("Renewing DHCP lease", "interface", iface)
	return m.Acquire(iface, hostname)
}

// prepareUdhcpcScript writes net's udhcpc event script and checks that it
// can actually be executed, returning its path, or "" to let udhcpc use its
// stock script. Falling back only costs the resolv.conf protection (renewals
// may rewrite it); handing udhcpc a script it cannot exec would cost the
// lease itself: the interface would get no address.
func (m *Manager) prepareUdhcpcScript() string {
	path, err := m.writeUdhcpcScript()
	if err == nil {
		err = m.probeUdhcpcScript(path)
	}
	if err != nil {
		m.logger.Warn("Using udhcpc's stock script; lease renewals may overwrite resolv.conf", "error", err)
		return ""
	}
	return path
}

func (m *Manager) udhcpcScriptDir() string {
	if m.scriptDir != "" {
		return m.scriptDir
	}
	return UdhcpcScriptDir
}

// writeUdhcpcScript writes net's udhcpc event script and returns its path.
// udhcpc runs it as root, so a directory others can write to is refused.
func (m *Manager) writeUdhcpcScript() (string, error) {
	dir := m.udhcpcScriptDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating %q: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("%q is writable by group or others", dir)
	}
	path := filepath.Join(dir, "udhcpc.script")
	if err := system.WriteSecureFile(path, UdhcpcScript("/etc/resolv.conf", types.DNSOwnedPath)); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return "", fmt.Errorf("making %q executable: %w", path, err)
	}
	return path, nil
}

// probeUdhcpcScript execs the script the way udhcpc will, with an event it
// ignores, so a noexec mount or a policy denial shows up before udhcpc
// depends on it.
func (m *Manager) probeUdhcpcScript(path string) error {
	if _, err := m.executor.ExecuteWithTimeout(IPCheckTimeout, path, "probe"); err != nil {
		return fmt.Errorf("cannot execute %q: %w", path, err)
	}
	return nil
}

// UdhcpcScript returns the event script udhcpc runs on bound/renew/deconfig.
// It applies the lease the way Debian's stock /etc/udhcpc/default.script
// does, except that it leaves resolv.conf alone while dnsOwned exists, i.e.
// while net owns DNS. The stock script rewrote resolv.conf on every renewal
// and only net's immutable lock stopped it; Tailscale accept_dns lifts that
// lock, and the renewal then raced tailscaled for the file.
func UdhcpcScript(resolvConf, dnsOwned string) string {
	return fmt.Sprintf(udhcpcScriptTemplate, shellQuote(resolvConf), shellQuote(dnsOwned))
}

// shellQuote single-quotes s for /bin/sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

const udhcpcScriptTemplate = `#!/bin/sh
# udhcpc event script written by net. Do not edit: net rewrites it.
RESOLV_CONF=%s
DNS_OWNED=%s

log() {
    logger -t "udhcpc[$PPID]" -p daemon.$1 "$interface: $2"
}

case $1 in
    bound|renew)
	busybox ifconfig $interface ${mtu:+mtu $mtu} \
	    $ip netmask $subnet ${broadcast:+broadcast $broadcast}

	crouter=$(busybox ip -4 route show dev $interface |
	          busybox awk '$1 == "default" { print $3; }')
	router="${router%%%% *}" # linux kernel supports only one (default) route
	if [ ".$router" != ".$crouter" ]; then
	    busybox ip -4 route flush exact 0.0.0.0/0 dev $interface
	fi
	if [ -n "$router" ]; then
	    [ ".$subnet" = .255.255.255.255 ] \
		    && onlink=onlink || onlink=
	    busybox ip -4 route add default via $router dev $interface $onlink
	fi

	# net (or Tailscale, for accept_dns) owns DNS: leave resolv.conf alone.
	if [ ! -e "$DNS_OWNED" ]; then
	    [ -n "$domain" ] && R="domain $domain" || R=""
	    for i in $dns; do
		R="$R
nameserver $i"
	    done
	    echo "$R" > "$RESOLV_CONF"
	fi

	log info "$1: IP=$ip/$subnet router=$router domain=\"$domain\" dns=\"$dns\" lease=$lease"
	;;

    deconfig)
	busybox ip link set $interface up
	busybox ip -4 addr flush dev $interface
	busybox ip -4 route flush dev $interface
	log notice "deconfigured"
	;;

    leasefail | nak)
	log err "configuration failed: $1: $message"
	;;

    probe)
	# net execs the script once to check it can run here.
	;;
esac
exit 0
`

// installDhclientHook installs net's dhclient enter hook (see
// DhclientEnterHook). It is skipped, with a warning, where it cannot work:
// no Debian-style hooks dir (other dhclient-scripts), or one others can
// write to. dhclient then behaves as before: renewals may rewrite
// resolv.conf. net never creates the dir.
func (m *Manager) installDhclientHook() {
	dir := m.hooksDir
	if dir == "" {
		dir = DhclientEnterHooksDir
	}
	err := func() error {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%q is writable by group or others", dir)
		}
		path := filepath.Join(dir, DhclientEnterHookName)
		if err := system.WriteSecureFile(path, DhclientEnterHook(types.DNSOwnedPath)); err != nil {
			return err
		}
		return os.Chmod(path, 0644)
	}()
	if err != nil {
		m.logger.Warn("dhclient enter hook not installed; lease renewals may overwrite resolv.conf", "error", err)
	}
}

// DhclientEnterHook returns net's dhclient enter hook. dhclient-script
// sources enter hooks after defining make_resolv_conf (the function that
// rewrites resolv.conf on BOUND/RENEW) and before calling it; while
// dnsOwned exists, i.e. while net owns DNS, the hook turns it into a no-op.
// This is the same rule net's udhcpc script applies, and the mechanism
// Debian's own resolved-enter hook uses. Sourced, so noexec does not matter.
func DhclientEnterHook(dnsOwned string) string {
	return fmt.Sprintf(`# dhclient enter hook installed by net. Do not edit: net rewrites it.
# While net owns DNS, lease renewals leave resolv.conf alone. Inert otherwise.
if [ -e %s ]; then
    make_resolv_conf() { :; }
fi
`, shellQuote(dnsOwned))
}

// udhcpcPidFile returns the pidfile path for udhcpc on the given interface.
func (m *Manager) udhcpcPidFile(iface string) string {
	return m.runDir() + "/udhcpc." + iface + ".pid"
}

// acquireUdhcpc uses udhcpc (BusyBox) for DHCP acquisition.
// udhcpc daemonizes after obtaining the lease and stays alive to handle
// renewals. The PID is written to /run/net/udhcpc.<iface>.pid so Release
// can terminate it cleanly (which sends a DHCPRELEASE via -R).
// The default BusyBox build sends only 3 DISCOVERs at 3s intervals (~9s
// window), which is too short for many USB ethernet adapters, so -t/-T
// widen the discovery window to ~18s, closer to dhclient's default.
func (m *Manager) acquireUdhcpc(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	// -i: interface
	// -n: exit if no lease acquired (so Acquire returns error on failure)
	// -p: pidfile so Release can find and kill the daemon
	// -R: send DHCPRELEASE when terminated (clean disconnect)
	// -B: set the broadcast flag in DISCOVER. Some embedded DHCP servers
	//     (e.g. IP radios, WISP gear) only reply via broadcast and silently
	//     drop clients that ask for unicast.
	// -t: number of DISCOVER retries (BusyBox default 3; we use 6)
	// -T: seconds between retries (BusyBox default 3)
	// -A: seconds to wait before re-trying after a full discover cycle
	// -s: net's event script (see UdhcpcScript), when it can run here
	// NOTE: no -q — udhcpc must stay running to renew the lease.
	args := []string{
		"-i", iface, "-n", "-p", m.udhcpcPidFile(iface), "-R", "-B",
		"-t", fmt.Sprintf("%d", UdhcpcDiscoverRetries),
		"-T", fmt.Sprintf("%d", UdhcpcDiscoverTimeout),
		"-A", fmt.Sprintf("%d", UdhcpcTryAgain),
	}
	if script := m.prepareUdhcpcScript(); script != "" {
		args = append(args, "-s", script)
	}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		args = append(args, "-x", "hostname:"+hostname)
	}

	_, err := m.executor.ExecuteWithTimeout(m.getUdhcpcTimeout(), "udhcpc", args...)
	if err != nil {
		// Clean up any partial state on failure
		m.Release(iface)
		return fmt.Errorf("udhcpc failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// acquireDhclient uses dhclient (ISC) as fallback
func (m *Manager) acquireDhclient(iface string, hostname string) error {
	// Release any existing clients first
	m.Release(iface)

	m.installDhclientHook()

	// Build dhclient command with optional hostname via config file
	// Use -1 (one attempt) to prevent dhclient from retrying indefinitely,
	// and -nw so it goes to background after obtaining a lease (keeping the
	// renewal daemon alive for lease renewal).
	dhclientTimeout := m.getDhclientTimeout()
	args := []string{fmt.Sprintf("%d", int(dhclientTimeout.Seconds())), "dhclient", "-v", "-1"}
	if hostname != "" {
		m.logger.Info("Sending hostname in DHCP request", "hostname", hostname)
		// Create interface-specific dhclient.conf to avoid race conditions
		// with concurrent DHCP operations on different interfaces
		confContent := fmt.Sprintf("send host-name \"%s\";\n", hostname)
		dhclientConf := m.runDir() + "/dhclient." + iface + ".conf"
		if err := system.WriteSecureFile(dhclientConf, confContent); err != nil {
			// Hostname was explicitly requested but we can't create config - this is a hard error
			return fmt.Errorf("failed to create dhclient config for hostname: %w", err)
		}
		args = append(args, "-cf", dhclientConf)
	}
	args = append(args, iface)

	// Start dhclient with timeout wrapper. The -1 flag ensures dhclient
	// exits after the first attempt (success or fail) rather than retrying
	// forever. The timeout wrapper is a safety net in case dhclient hangs.
	//
	// The executor deadline must exceed the inner `timeout` value, otherwise
	// the default 30s command timeout SIGKILLs the `timeout` process before
	// dhclient's own window elapses — SIGKILL can't be forwarded, so dhclient
	// is orphaned and any lease past 30s is silently lost. Give a 5s margin.
	_, err := m.executor.ExecuteWithTimeout(dhclientTimeout+5*time.Second, "timeout", args...)
	if err != nil {
		// Clean up any partial state on failure
		m.Release(iface)
		return fmt.Errorf("dhclient failed: %w", err)
	}

	m.logAcquiredIP(iface)
	return nil
}

// logAcquiredIP logs the IP address after successful DHCP
func (m *Manager) logAcquiredIP(iface string) {
	ipOutput, err := m.executor.ExecuteWithTimeout(IPCheckTimeout, "ip", "addr", "show", iface)
	if err == nil {
		ip := m.parseIPAddress(ipOutput)
		if ip != nil {
			m.logger.Info("Address acquired", "ip", ip.String())
		}
	}
}

// parseIPAddress extracts the first IPv4 address from ip addr output
func (m *Manager) parseIPAddress(output string) net.IP {
	return system.ParseIPFromOutput(output)
}
