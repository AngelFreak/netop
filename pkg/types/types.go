package types

import (
	"context"
	"net"
	"time"
)

// RuntimeDir is the directory for temporary runtime files (configs, pid files)
// Using /run/net/ instead of /tmp/ to avoid symlink attacks
const RuntimeDir = "/run/net"

// Config represents the main configuration structure
type Config struct {
	Common   CommonConfig             `yaml:"common" mapstructure:"common"`
	Ignored  IgnoredConfig            `yaml:"ignored" mapstructure:"ignored"`
	VPN      map[string]VPNConfig     `yaml:"vpn" mapstructure:"vpn"`
	Networks map[string]NetworkConfig `yaml:",inline" mapstructure:",inline"`
}

// CommonConfig holds default settings applied to all connections
type CommonConfig struct {
	MAC      string        `yaml:"mac" mapstructure:"mac"`
	DNS      []string      `yaml:"dns" mapstructure:"dns"`
	Hostname string        `yaml:"hostname" mapstructure:"hostname"`
	VPN      string        `yaml:"vpn" mapstructure:"vpn"`
	Timeouts TimeoutConfig `yaml:"timeouts" mapstructure:"timeouts"`
}

// TimeoutConfig holds configurable timeout values (in seconds)
// All values default to sensible values if not specified
type TimeoutConfig struct {
	DHCP        int `yaml:"dhcp" mapstructure:"dhcp"`               // DHCP lease acquisition (default: 30s)
	Association int `yaml:"association" mapstructure:"association"` // WiFi association (default: 30s)
	Command     int `yaml:"command" mapstructure:"command"`         // General command timeout (default: 30s)
	Carrier     int `yaml:"carrier" mapstructure:"carrier"`         // Carrier detection (default: 5s)
	Portal      int `yaml:"portal" mapstructure:"portal"`           // Captive portal probe (default: 3s)
}

// GetDHCPTimeout returns DHCP timeout with default fallback
func (t *TimeoutConfig) GetDHCPTimeout() time.Duration {
	if t.DHCP > 0 {
		return time.Duration(t.DHCP) * time.Second
	}
	return 30 * time.Second
}

// GetAssociationTimeout returns association timeout with default fallback
func (t *TimeoutConfig) GetAssociationTimeout() time.Duration {
	if t.Association > 0 {
		return time.Duration(t.Association) * time.Second
	}
	return 30 * time.Second
}

// GetCommandTimeout returns command timeout with default fallback
func (t *TimeoutConfig) GetCommandTimeout() time.Duration {
	if t.Command > 0 {
		return time.Duration(t.Command) * time.Second
	}
	return 30 * time.Second
}

// GetCarrierTimeout returns carrier detection timeout with default fallback
func (t *TimeoutConfig) GetCarrierTimeout() time.Duration {
	if t.Carrier > 0 {
		return time.Duration(t.Carrier) * time.Second
	}
	return 5 * time.Second
}

// GetPortalTimeout returns the captive-portal probe timeout with default fallback
func (t *TimeoutConfig) GetPortalTimeout() time.Duration {
	if t.Portal > 0 {
		return time.Duration(t.Portal) * time.Second
	}
	return 3 * time.Second
}

// IgnoredConfig contains interfaces to ignore
type IgnoredConfig struct {
	Interfaces []string `yaml:"interfaces" mapstructure:"interfaces"`
}

// VPNConfig represents VPN configuration
type VPNConfig struct {
	Type          string `yaml:"type" mapstructure:"type"`                     // "openvpn", "wireguard", "tailscale", or "netbird"
	Config        string `yaml:"config" mapstructure:"config"`                 // Inline config (OpenVPN/WireGuard)
	Address       string `yaml:"address" mapstructure:"address"`               // WireGuard IP
	Interface     string `yaml:"interface" mapstructure:"interface"`           // WireGuard interface name
	Gateway       bool   `yaml:"gateway" mapstructure:"gateway"`               // Route all traffic via VPN (WireGuard)
	AuthKey       string `yaml:"auth_key" mapstructure:"auth_key"`             // Tailscale auth key
	ExitNode      string `yaml:"exit_node" mapstructure:"exit_node"`           // Tailscale exit node
	AcceptRoutes  bool   `yaml:"accept_routes" mapstructure:"accept_routes"`   // Tailscale accept routes
	SetupKey      string `yaml:"setup_key" mapstructure:"setup_key"`           // NetBird setup key
	ManagementURL string `yaml:"management_url" mapstructure:"management_url"` // NetBird management URL
	Profile       string `yaml:"profile" mapstructure:"profile"`               // Tailscale/NetBird profile for account switching
}

// NetworkConfig represents a network configuration
type NetworkConfig struct {
	Interface string   `yaml:"interface" mapstructure:"interface"`
	SSID      string   `yaml:"ssid" mapstructure:"ssid"`
	PSK       string   `yaml:"psk" mapstructure:"psk"`
	WPA       string   `yaml:"wpa" mapstructure:"wpa"`
	ApAddr    string   `yaml:"ap-addr" mapstructure:"ap-addr"`
	Addr      string   `yaml:"addr" mapstructure:"addr"`
	Gateway   string   `yaml:"gateway" mapstructure:"gateway"`
	Routes    []string `yaml:"routes" mapstructure:"routes"`
	DNS       []string `yaml:"dns" mapstructure:"dns"`
	MAC       string   `yaml:"mac" mapstructure:"mac"`
	Hostname  string   `yaml:"hostname" mapstructure:"hostname"`
	VPN       string   `yaml:"vpn" mapstructure:"vpn"`
	// Metric is the default-route metric (lower = preferred). 0 means use the
	// built-in default (100 for wired, 600 for WiFi) so wired wins when both
	// are up simultaneously. Matches NetworkManager's default convention.
	Metric int `yaml:"metric" mapstructure:"metric"`
}

// DefaultRouteMetric returns the default-route metric for this network,
// falling back to type-appropriate defaults when Metric is 0.
func (n *NetworkConfig) DefaultRouteMetric() int {
	if n.Metric > 0 {
		return n.Metric
	}
	if n.SSID != "" {
		return 600
	}
	return 100
}

// WiFiNetwork represents a discovered WiFi network
type WiFiNetwork struct {
	SSID      string
	BSSID     string
	Signal    int
	Security  string
	Frequency int
}

// Connection represents an active network connection
type Connection struct {
	Interface string
	SSID      string
	State     string
	IP        net.IP
	Gateway   net.IP
	DNS       []net.IP
}

// VPNStatus represents VPN connection status
type VPNStatus struct {
	Name      string
	Type      string
	Connected bool
	Interface string
	IP        net.IP
}

// HotspotConfig represents hotspot configuration
type HotspotConfig struct {
	Interface string   `yaml:"interface" mapstructure:"interface"`
	SSID      string   `yaml:"ssid" mapstructure:"ssid"`
	Password  string   `yaml:"password" mapstructure:"password"`
	Channel   int      `yaml:"channel" mapstructure:"channel"`
	IPRange   string   `yaml:"ip_range" mapstructure:"ip_range"` // DHCP range, e.g., "192.168.50.50,192.168.50.150"
	Gateway   string   `yaml:"gateway" mapstructure:"gateway"`   // e.g., "192.168.50.1"
	Netmask   string   `yaml:"netmask" mapstructure:"netmask"`   // CIDR prefix length, e.g., "24" (default: "24")
	DNS       []string `yaml:"dns" mapstructure:"dns"`
}

// HotspotStatus represents hotspot status
type HotspotStatus struct {
	Interface string
	SSID      string
	Running   bool
	Clients   int
	Gateway   net.IP
}

// DHCPServerConfig represents DHCP server configuration
type DHCPServerConfig struct {
	Interface string   `yaml:"interface" mapstructure:"interface"`
	IPRange   string   `yaml:"ip_range" mapstructure:"ip_range"` // e.g., "192.168.100.50,192.168.100.150"
	Gateway   string   `yaml:"gateway" mapstructure:"gateway"`   // e.g., "192.168.100.1"
	Netmask   string   `yaml:"netmask" mapstructure:"netmask"`   // CIDR bits, e.g., "24" for /24. Defaults to "24"
	DNS       []string `yaml:"dns" mapstructure:"dns"`
	LeaseTime string   `yaml:"lease_time" mapstructure:"lease_time"` // e.g., "12h"
}

// Interfaces for dependency injection and testing

// SystemExecutor handles system command execution
type SystemExecutor interface {
	Execute(cmd string, args ...string) (string, error)
	ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error)
	ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error)
	ExecuteWithInput(cmd string, input string, args ...string) (string, error)
	ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error)
	HasCommand(cmd string) bool
}

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// PortalStatus classifies internet reachability as seen by the portal probe.
type PortalStatus int

const (
	// PortalStatusUnknown is the zero value — deliberately NOT online, so a
	// forgotten status field or future enum value can never fail open into
	// "internet works". CLI code treats it like offline.
	PortalStatusUnknown PortalStatus = iota
	// PortalStatusOnline means the probe returned the expected response — internet works.
	PortalStatusOnline
	// PortalStatusPortal means a captive portal intercepted the probe.
	PortalStatusPortal
	// PortalStatusOffline means the probe failed or returned a non-portal error
	// status — no working internet, but no portal positively identified either.
	PortalStatusOffline
)

// PortalResult is the outcome of a captive-portal probe.
//
// Display-safety contract: implementations MUST only populate PortalURL and
// ProbeURL with validated absolute http/https URLs that contain no control or
// format characters — CLI code prints these fields verbatim to the terminal.
type PortalResult struct {
	Status PortalStatus
	// PortalURL is the portal's login URL taken from the redirect Location
	// header, when the portal provided a usable one. Empty when the portal
	// didn't redirect (DNS-hijack style) or sent an unusable/unsafe Location —
	// open ProbeURL in a browser instead.
	PortalURL string
	// ProbeURL is the probe endpoint that was used. When PortalURL is empty,
	// opening ProbeURL in a browser will trigger the portal's redirect.
	ProbeURL string
}

// PortalDetector probes for internet connectivity and captive portals.
// Transport failures and unexpected error statuses are reported as
// PortalStatusOffline, not as errors; Check returns a non-nil error only for
// misconfiguration (e.g. an https probe URL, which portals cannot intercept).
// The probe uses the process's normal routing (default route); it is not
// bound to a specific interface.
type PortalDetector interface {
	Check() (PortalResult, error)
}

// WiFiManager handles WiFi operations
type WiFiManager interface {
	Scan() ([]WiFiNetwork, error)
	Connect(ssid, password, hostname string) error
	ConnectWithBSSID(ssid, password, bssid, hostname string) error
	Disconnect() error
	ListConnections() ([]Connection, error)
	GetInterface() string
}

// VPNManager handles VPN operations
type VPNManager interface {
	Connect(name string) error
	Disconnect(name string) error
	ListVPNs() ([]VPNStatus, error)
	GenerateWireGuardKey() (private, public string, err error)
}

// NetworkManager handles network configuration
type NetworkManager interface {
	SetDNS(servers []string) error
	ClearDNS() error
	// ClearDNSIfOwned clears DNS only if netop set it. Returns (cleared, err).
	ClearDNSIfOwned() (bool, error)
	LockDNS()
	SetMAC(iface, mac string) error
	GetMAC(iface string) (string, error)
	SetIP(iface, addr, gateway string, metric int) error
	AddRoute(iface, destination, gateway string) error
	FlushRoutes(iface string) error
	StartDHCP(iface string, hostname string) error
	DHCPRenew(iface string, hostname string) error
	ConnectToConfiguredNetwork(config *NetworkConfig, password string, wifiMgr WiFiManager) error
	GetConnectionInfo(iface string) (*Connection, error)
	// Disconnect releases DHCP, flushes addresses/routes, and brings the link down
	// for a single interface. Safe to call on an already-down interface.
	Disconnect(iface string) error
	// DisconnectAll tears down every non-loopback/non-virtual interface that has
	// an IPv4 address assigned. Used by `net stop` to clean up both wired and WiFi.
	// Returns the list of interfaces that were torn down.
	DisconnectAll() []string
}

// ConfigManager handles configuration loading and management
type ConfigManager interface {
	LoadConfig(path string) (*Config, error)
	GetNetworkConfig(name string) (*NetworkConfig, error)
	GetVPNConfig(name string) (*VPNConfig, error)
	MergeWithCommon(networkName string, config *NetworkConfig) *NetworkConfig
	GetConfig() *Config
}

// HotspotManager handles WiFi hotspot operations
type HotspotManager interface {
	Start(config *HotspotConfig) error
	Stop() error
	GetStatus() (*HotspotStatus, error)
}

// DHCPLease represents a single DHCP lease from the dnsmasq lease file
type DHCPLease struct {
	Expiry   time.Time
	MAC      string
	IP       string
	Hostname string
}

// DHCPManager handles DHCP server operations (running dnsmasq for hotspot)
type DHCPManager interface {
	Start(config *DHCPServerConfig) error
	Stop() error
	IsRunning() bool
	GetLeases() ([]DHCPLease, error)
	GetCurrentConfig() *DHCPServerConfig
}

// DHCPClientManager handles DHCP client operations (obtaining leases from a server)
// This is distinct from DHCPManager which handles DHCP server operations
type DHCPClientManager interface {
	Acquire(iface string, hostname string) error
	Release(iface string) error
	Renew(iface string, hostname string) error
}

// Route describes a single routing table entry in structured form. It replaces
// the fragile text parsing of `ip route show` output.
//
// A default route has Dst == nil (or the "default"/0.0.0.0/0 destination). Such a
// route may be either:
//   - via a gateway:  Gw is set (e.g. "192.168.1.1")  — a normal LAN default route
//   - device-only:    Gw == "" and Iface is set        — e.g. `default dev wg0`
//
// Callers MUST branch on route existence and the Gw/Iface fields, NOT on
// "Gw != \"\" && Iface != \"\"" — a device-only default route has an empty Gw and
// is still a valid, restorable route. Mishandling this is the motivating bug.
type Route struct {
	// Dst is the destination network in CIDR form. Empty means the default route.
	Dst string
	// Gw is the gateway IP as a string, or "" for a device-only route.
	Gw string
	// Iface is the outgoing interface name (may be "" if unresolved).
	Iface string
	// Metric is the route priority (0 if unset).
	Metric int
}

// IsDefault reports whether this route is the default route (destination 0/0).
func (r Route) IsDefault() bool {
	return r.Dst == "" || r.Dst == "default" || r.Dst == "0.0.0.0/0" || r.Dst == "::/0"
}

// RouteManager provides structured access to the kernel routing table via
// netlink, replacing text-parsing of the `ip route` command. Read operations
// (GetDefaultRoute, ListRoutes) are unprivileged; write operations require
// CAP_NET_ADMIN, which net already holds. Implementations must return a clear
// error (never panic) when netlink is restricted (e.g. some containers).
type RouteManager interface {
	// GetDefaultRoute returns the current IPv4 default route, or an error if none
	// exists. The returned Route correctly represents both gateway and device-only
	// default routes (see Route).
	GetDefaultRoute() (*Route, error)
	// GetDefaultRouteForIface returns the IPv4 default route whose outgoing
	// interface is iface, or an error if none exists on that interface.
	GetDefaultRouteForIface(iface string) (*Route, error)
	// ReplaceDefault installs (or replaces) THE IPv4 default route: it clears
	// every existing default route, then installs one via iface. If gw is "",
	// a device-only default route is installed. metric of 0 means unset. Use
	// this when there must be exactly one default route (e.g. VPN restore).
	ReplaceDefault(iface, gw string, metric int) error
	// SetDefaultForIface installs the IPv4 default route via iface, replacing
	// only the default route already on THAT interface and leaving any default
	// routes on other interfaces intact. Use this for per-interface config that
	// must coexist with other links (multi-homing). metric of 0 means unset.
	SetDefaultForIface(iface, gw string, metric int) error
	// AddRoute adds a route to destination (CIDR or bare host IP) via gw on
	// iface. If gw is "", a device-scoped route is added. Returns an error if
	// the route already exists.
	AddRoute(iface, destination, gw string) error
	// ReplaceRoute installs a route to destination (CIDR or bare host IP) via gw
	// on iface, replacing any existing route to the same destination. If gw is
	// "", a device-scoped route is installed.
	ReplaceRoute(iface, destination, gw string) error
	// DelRoute removes the route to destination (CIDR or bare host IP). Missing
	// routes are not treated as errors.
	DelRoute(destination string) error
	// FlushRoutes removes all IPv4 routes associated with iface.
	FlushRoutes(iface string) error
	// ListRoutes returns all IPv4 routes in the main table.
	ListRoutes() ([]Route, error)
}

// AddrManager provides structured access to interface IPv4 addresses via
// netlink, replacing text-parsing of `ip addr`. Read operations (GetFirstIPv4)
// are unprivileged; write operations (Add/Replace/Flush) require CAP_NET_ADMIN.
// Implementations must return a clear error (never panic) when netlink is
// restricted.
type AddrManager interface {
	// GetFirstIPv4 returns the first IPv4 address assigned to iface (without the
	// prefix length), or nil if the interface has no IPv4 address. Replaces
	// parsing the first `inet` line of `ip addr show`.
	GetFirstIPv4(iface string) (net.IP, error)
	// Add assigns the CIDR address (e.g. "10.0.0.1/24") to iface.
	Add(iface, cidr string) error
	// Replace assigns the CIDR address to iface, replacing any existing address
	// with the same prefix (like `ip addr replace`).
	Replace(iface, cidr string) error
	// Flush removes all IPv4 addresses from iface.
	Flush(iface string) error
}

// LinkManager provides structured access to network links (interfaces) via
// netlink, replacing text-parsing of `ip link`. Read operations (Exists,
// ListByType, GetMAC) are unprivileged; write operations require CAP_NET_ADMIN.
// Implementations must return a clear error (never panic) when netlink is
// restricted.
type LinkManager interface {
	// SetUp brings the interface administratively up.
	SetUp(iface string) error
	// SetDown brings the interface administratively down.
	SetDown(iface string) error
	// Delete removes a virtual interface (e.g. a WireGuard device).
	Delete(iface string) error
	// Exists reports whether an interface with the given name exists.
	Exists(iface string) (bool, error)
	// AddWireGuard creates a WireGuard interface with the given name.
	AddWireGuard(iface string) error
	// ListByType returns the names of all interfaces of the given link type
	// (e.g. "wireguard"), in kernel order.
	ListByType(linkType string) ([]string, error)
	// GetMAC returns the hardware (MAC) address of iface as a string.
	GetMAC(iface string) (string, error)
	// SetMAC sets the hardware (MAC) address of iface. The interface must be
	// down; callers are responsible for down/up sequencing.
	SetMAC(iface, mac string) error
}

// FirewallManager configures the IPv4 NAT/forwarding rules that let clients on
// an internal interface (hotspot or DHCP-served) reach the internet through an
// outbound interface. It wraps iptables (via github.com/coreos/go-iptables),
// which reduces duplicate-rule and rule-listing bugs versus building iptables
// command lines by hand. Implementations must return a clear error (never
// panic) when iptables is unavailable.
type FirewallManager interface {
	// EnableNAT installs the three rules needed to share internet from
	// internalIface out through outIface: MASQUERADE on outIface, FORWARD accept
	// for traffic from internalIface, and FORWARD accept for established/related
	// return traffic. Idempotent — re-applying is a no-op.
	EnableNAT(internalIface, outIface string) error
	// DisableNAT removes the rules installed by EnableNAT. Missing rules are not
	// treated as errors.
	DisableNAT(internalIface, outIface string) error
}
