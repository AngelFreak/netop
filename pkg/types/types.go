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

// IgnoredConfig contains interfaces to ignore
type IgnoredConfig struct {
	Interfaces []string `yaml:"interfaces" mapstructure:"interfaces"`
}

// VPNConfig represents VPN configuration
type VPNConfig struct {
	Type      string `yaml:"type" mapstructure:"type"` // "openvpn" or "wireguard"
	Config    string `yaml:"config" mapstructure:"config"`
	Address   string `yaml:"address" mapstructure:"address"`     // WireGuard
	Interface string `yaml:"interface" mapstructure:"interface"` // WireGuard
	Gateway   bool   `yaml:"gateway" mapstructure:"gateway"`     // WireGuard
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
	IPRange   string   `yaml:"ip_range" mapstructure:"ip_range"`     // DHCP range, e.g., "192.168.50.50,192.168.50.150"
	Gateway   string   `yaml:"gateway" mapstructure:"gateway"`       // e.g., "192.168.50.1"
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
	IPRange   string   `yaml:"ip_range" mapstructure:"ip_range"`     // e.g., "192.168.100.50,192.168.100.150"
	Gateway   string   `yaml:"gateway" mapstructure:"gateway"`       // e.g., "192.168.100.1"
	Netmask   string   `yaml:"netmask" mapstructure:"netmask"`       // CIDR bits, e.g., "24" for /24. Defaults to "24"
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
	SetMAC(iface, mac string) error
	GetMAC(iface string) (string, error)
	SetIP(iface, addr, gateway string) error
	AddRoute(iface, destination, gateway string) error
	FlushRoutes(iface string) error
	StartDHCP(iface string, hostname string) error
	DHCPRenew(iface string, hostname string) error
	ConnectToConfiguredNetwork(config *NetworkConfig, password string, wifiMgr WiFiManager) error
	GetConnectionInfo(iface string) (*Connection, error)
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

// DHCPManager handles DHCP server operations (running dnsmasq for hotspot)
type DHCPManager interface {
	Start(config *DHCPServerConfig) error
	Stop() error
	IsRunning() bool
}

// DHCPClientManager handles DHCP client operations (obtaining leases from a server)
// This is distinct from DHCPManager which handles DHCP server operations
type DHCPClientManager interface {
	Acquire(iface string, hostname string) error
	Release(iface string) error
	Renew(iface string, hostname string) error
}
