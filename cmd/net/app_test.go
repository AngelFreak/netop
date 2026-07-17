package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	fakenetlink "github.com/angelfreak/net/pkg/netlink/fake"
	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// testLogger implements types.Logger for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Warn(msg string, args ...interface{})  {}
func (l *testLogger) Error(msg string, args ...interface{}) {}

// testExecutor implements types.SystemExecutor for testing
type testExecutor struct {
	executeFunc func(name string, args ...string) (string, error)
}

func (e *testExecutor) Execute(name string, args ...string) (string, error) {
	if e.executeFunc != nil {
		return e.executeFunc(name, args...)
	}
	return "", nil
}

func (e *testExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return e.Execute(cmd, args...)
}

func (e *testExecutor) HasCommand(cmd string) bool {
	return true
}

// testConfigManager implements types.ConfigManager for testing
type testConfigManager struct {
	config                *types.Config
	networkConfig         *types.NetworkConfig
	networkErr            error
	mergeWithCommonCalled bool
	lastMergedNetwork     string
	vpnExplicitlyDisabled map[string]bool // networks where vpn: is explicitly empty
}

func (c *testConfigManager) LoadConfig(path string) (*types.Config, error) {
	return c.config, nil
}

func (c *testConfigManager) GetConfig() *types.Config {
	return c.config
}

func (c *testConfigManager) GetNetworkConfig(name string) (*types.NetworkConfig, error) {
	if c.networkErr != nil {
		return nil, c.networkErr
	}
	return c.networkConfig, nil
}

func (c *testConfigManager) MergeWithCommon(name string, config *types.NetworkConfig) *types.NetworkConfig {
	c.mergeWithCommonCalled = true
	c.lastMergedNetwork = name
	// Apply basic merge logic for testing: inherit common settings if not set in network config
	if c.config != nil && config != nil {
		merged := *config
		if len(merged.DNS) == 0 && len(c.config.Common.DNS) > 0 {
			merged.DNS = c.config.Common.DNS
		}
		if merged.MAC == "" && c.config.Common.MAC != "" {
			merged.MAC = c.config.Common.MAC
		}
		if merged.Hostname == "" && c.config.Common.Hostname != "" {
			merged.Hostname = c.config.Common.Hostname
		}
		// Only inherit VPN from common if not explicitly disabled for this network
		if merged.VPN == "" && c.config.Common.VPN != "" {
			if c.vpnExplicitlyDisabled == nil || !c.vpnExplicitlyDisabled[name] {
				merged.VPN = c.config.Common.VPN
			}
		}
		return &merged
	}
	return config
}

func (c *testConfigManager) GetVPNConfig(name string) (*types.VPNConfig, error) {
	if c.config != nil && c.config.VPN != nil {
		if vpn, ok := c.config.VPN[name]; ok {
			return &vpn, nil
		}
	}
	return nil, errors.New("vpn not found")
}

// testWiFiManager implements types.WiFiManager for testing
type testWiFiManager struct {
	connections []types.Connection
	networks    []types.WiFiNetwork
	scanErr     error
	connectErr  error
	listErr     error
}

func (w *testWiFiManager) Scan() ([]types.WiFiNetwork, error) {
	if w.scanErr != nil {
		return nil, w.scanErr
	}
	return w.networks, nil
}

func (w *testWiFiManager) Connect(ssid, password, hostname string) error {
	return w.connectErr
}

func (w *testWiFiManager) ConnectWithBSSID(ssid, password, bssid, hostname string) error {
	return w.connectErr
}

func (w *testWiFiManager) Disconnect() error {
	return nil
}

func (w *testWiFiManager) ListConnections() ([]types.Connection, error) {
	if w.listErr != nil {
		return nil, w.listErr
	}
	return w.connections, nil
}

func (w *testWiFiManager) GetInterface() string {
	return "wlan0"
}

// testVPNManager implements types.VPNManager for testing
type testVPNManager struct {
	vpns       []types.VPNStatus
	connectErr error
	listErr    error
	genkeyErr  error
}

func (v *testVPNManager) Connect(name string) error {
	return v.connectErr
}

func (v *testVPNManager) Disconnect(name string) error {
	return nil
}

func (v *testVPNManager) ListVPNs() ([]types.VPNStatus, error) {
	if v.listErr != nil {
		return nil, v.listErr
	}
	return v.vpns, nil
}

func (v *testVPNManager) GenerateWireGuardKey() (string, string, error) {
	if v.genkeyErr != nil {
		return "", "", v.genkeyErr
	}
	return "privatekey123", "publickey456", nil
}

// testNetworkManager implements types.NetworkManager for testing
type testNetworkManager struct {
	mac            string
	setMACErr      error
	setDNSErr      error
	dhcpErr        error
	connectErr     error
	connectionInfo *types.Connection
	connectionErr  error
}

func (n *testNetworkManager) SetMAC(iface, mac string) error {
	return n.setMACErr
}

func (n *testNetworkManager) GetMAC(iface string) (string, error) {
	return n.mac, nil
}

func (n *testNetworkManager) SetDNS(servers []string) error {
	return n.setDNSErr
}

func (n *testNetworkManager) ClearDNS() error {
	return nil
}

func (n *testNetworkManager) ClearDNSIfOwned() (bool, error) {
	return false, nil
}

func (n *testNetworkManager) LockDNS() {
}

func (n *testNetworkManager) DHCPRenew(iface, hostname string) error {
	return n.dhcpErr
}

func (n *testNetworkManager) ConnectToConfiguredNetwork(config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
	// Simulate real behavior: auto-detect sets config.Interface
	if config.Interface == "" {
		if config.SSID != "" {
			config.Interface = "wlan0"
		} else {
			config.Interface = "eth0"
		}
	}
	return n.connectErr
}

func (n *testNetworkManager) AddRoute(iface, destination, gateway string) error {
	return nil
}

func (n *testNetworkManager) FlushRoutes(iface string) error {
	return nil
}

func (n *testNetworkManager) StartDHCP(iface string, hostname string) error {
	return nil
}

func (n *testNetworkManager) SetIP(iface, addr, gateway string, metric int) error {
	return nil
}

func (n *testNetworkManager) GetConnectionInfo(iface string) (*types.Connection, error) {
	if n.connectionErr != nil {
		return nil, n.connectionErr
	}
	if n.connectionInfo != nil {
		return n.connectionInfo, nil
	}
	return &types.Connection{Interface: iface, State: "connected"}, nil
}

func (n *testNetworkManager) Disconnect(iface string) error {
	return nil
}

func (n *testNetworkManager) DisconnectAll() []string {
	return nil
}

// testHotspotManager implements types.HotspotManager for testing
type testHotspotManager struct {
	status    *types.HotspotStatus
	startErr  error
	stopErr   error
	statusErr error
}

func (h *testHotspotManager) Start(config *types.HotspotConfig) error {
	return h.startErr
}

func (h *testHotspotManager) Stop() error {
	return h.stopErr
}

func (h *testHotspotManager) GetStatus() (*types.HotspotStatus, error) {
	if h.statusErr != nil {
		return nil, h.statusErr
	}
	if h.status == nil {
		return &types.HotspotStatus{Running: false}, nil
	}
	return h.status, nil
}

// testDHCPManager implements types.DHCPManager for testing
type testDHCPManager struct {
	running       bool
	startErr      error
	stopErr       error
	leases        []types.DHCPLease
	leasesErr     error
	currentConfig *types.DHCPServerConfig
}

func (d *testDHCPManager) Start(config *types.DHCPServerConfig) error {
	return d.startErr
}

func (d *testDHCPManager) Stop() error {
	return d.stopErr
}

func (d *testDHCPManager) IsRunning() bool {
	return d.running
}

func (d *testDHCPManager) GetLeases() ([]types.DHCPLease, error) {
	return d.leases, d.leasesErr
}

func (d *testDHCPManager) GetCurrentConfig() *types.DHCPServerConfig {
	return d.currentConfig
}

// Helper to create a test App
func newTestApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return &App{
		Logger:     &testLogger{},
		Executor:   &testExecutor{},
		ConfigMgr:  &testConfigManager{},
		WiFiMgr:    &testWiFiManager{},
		VPNMgr:     &testVPNManager{},
		NetworkMgr: &testNetworkManager{},
		HotspotMgr: &testHotspotManager{},
		DHCPMgr:    &testDHCPManager{},
		Interface:  "wlan0",
		Stdout:     stdout,
		Stderr:     stderr,
	}, stdout, stderr
}

func TestApp_RunList_Success(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{
				Interface: "wlan0",
				SSID:      "TestNetwork",
				State:     "connected",
				IP:        net.ParseIP("192.168.1.100"),
				Gateway:   net.ParseIP("192.168.1.1"),
				DNS:       []net.IP{net.ParseIP("8.8.8.8")},
			},
		},
	}

	err := app.RunList()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "TestNetwork")
	assert.Contains(t, stdout.String(), "192.168.1.100")
}

func TestApp_RunList_NoConnections(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunList()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "No active connections")
}

func TestApp_RunList_Error(t *testing.T) {
	app, _, stderr := newTestApp()
	app.WiFiMgr = &testWiFiManager{listErr: errors.New("list failed")}

	err := app.RunList()
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "list failed")
}

func TestApp_RunScan_Success(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.WiFiMgr = &testWiFiManager{
		networks: []types.WiFiNetwork{
			{SSID: "Network1", BSSID: "00:11:22:33:44:55", Signal: -50, Security: "WPA2"},
			{SSID: "OpenNet", BSSID: "AA:BB:CC:DD:EE:FF", Signal: -60, Security: "Open"},
		},
	}

	err := app.RunScan(false)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Scanning for networks...")
	assert.Contains(t, stdout.String(), "Found 2 networks")
	assert.Contains(t, stdout.String(), "Network1")
	assert.Contains(t, stdout.String(), "OpenNet")
}

func TestApp_RunScan_ProgressSuppressedInDebugMode(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.Debug = true
	app.WiFiMgr = &testWiFiManager{
		networks: []types.WiFiNetwork{
			{SSID: "Network1", BSSID: "00:11:22:33:44:55", Signal: -50, Security: "WPA2"},
		},
	}

	err := app.RunScan(false)
	assert.NoError(t, err)
	// Progress messages should NOT appear in debug mode
	assert.NotContains(t, stdout.String(), "Scanning for networks...")
	assert.NotContains(t, stdout.String(), "Found 1 networks")
	// But the actual network output should still appear
	assert.Contains(t, stdout.String(), "Network1")
}

func TestApp_RunScan_OpenOnly(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.WiFiMgr = &testWiFiManager{
		networks: []types.WiFiNetwork{
			{SSID: "Network1", BSSID: "00:11:22:33:44:55", Signal: -50, Security: "WPA2"},
			{SSID: "OpenNet", BSSID: "AA:BB:CC:DD:EE:FF", Signal: -60, Security: "Open"},
		},
	}

	err := app.RunScan(true)
	assert.NoError(t, err)
	assert.NotContains(t, stdout.String(), "Network1")
	assert.Contains(t, stdout.String(), "OpenNet")
}

func TestApp_RunScan_Error(t *testing.T) {
	app, _, stderr := newTestApp()
	app.WiFiMgr = &testWiFiManager{scanErr: errors.New("scan failed")}

	err := app.RunScan(false)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "scan failed")
}

func TestApp_RunConnect_DirectSSID(t *testing.T) {
	app, stdout, _ := newTestApp()
	// Config loaded fine (non-nil) but the name isn't a configured network
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connecting to WiFi...")
	assert.Contains(t, stdout.String(), "Connected!")
}

func TestApp_RunConnect_SSIDMatchesConfiguredNetwork(t *testing.T) {
	app, stdout, _ := newTestApp()
	// GetNetworkConfig fails for the given name, but its SSID uniquely matches
	// a configured network, so that network's config (and VPN) should apply.
	cfgMgr := &testConfigManager{
		networkErr: errors.New("not found"),
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "MyWifi", VPN: "work"},
			},
		},
	}
	app.ConfigMgr = cfgMgr
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "MyWifi", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("MyWifi", "pw")
	assert.NoError(t, err)
	// Configured path used the network NAME, not the SSID.
	assert.True(t, cfgMgr.mergeWithCommonCalled, "should use configured-network path")
	assert.Equal(t, "home", cfgMgr.lastMergedNetwork)
	// connectVPN received "home" and resolved its vpn: work.
	assert.Contains(t, stdout.String(), "Connecting to VPN 'work'")
	assert.Contains(t, stdout.String(), "VPN connected!")
}

func TestApp_RunConnect_AmbiguousSSIDFallsBackToDirect(t *testing.T) {
	app, stdout, _ := newTestApp()
	// Two configured networks share the same SSID — ambiguous, so connect as a
	// plain SSID rather than guessing which config applies.
	cfgMgr := &testConfigManager{
		networkErr: errors.New("not found"),
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home":  {SSID: "MyWifi"},
				"guest": {SSID: "MyWifi", VPN: "work"},
			},
		},
	}
	app.ConfigMgr = cfgMgr
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "MyWifi", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("MyWifi", "pw")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connecting to WiFi...")
	// Direct-SSID path: connectVPN("MyWifi") finds no Networks entry and
	// Common.VPN is empty, so no VPN is attempted.
	assert.NotContains(t, stdout.String(), "Connecting to VPN")
	assert.False(t, cfgMgr.mergeWithCommonCalled, "ambiguous SSID must not use configured path")
}

func TestApp_RunConnect_FailsWhenConfigNotLoaded(t *testing.T) {
	app, _, stderr := newTestApp()
	// GetConfig() returns nil — the config file failed to load. Connect must
	// not silently fall back to treating the name as a plain SSID.
	app.ConfigMgr = &testConfigManager{config: nil, networkErr: errors.New("config not loaded")}
	app.WiFiMgr = &testWiFiManager{}

	err := app.RunConnect("home", "")
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "configuration failed to load")
}

func TestApp_RunConnect_ConfiguredNetwork(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		networkConfig: &types.NetworkConfig{SSID: "ConfiguredNet", PSK: "savedpass"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connecting to WiFi...")
	assert.Contains(t, stdout.String(), "Connected!")
}

func TestApp_RunConnect_WiredNetwork(t *testing.T) {
	app, stdout, _ := newTestApp()
	// Wired profile: no SSID
	app.ConfigMgr = &testConfigManager{
		networkConfig: &types.NetworkConfig{},
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"wired": {},
			},
		},
	}
	app.NetworkMgr = &testNetworkManager{
		connectionInfo: &types.Connection{
			Interface: "eth0",
			State:     "connected",
			IP:        net.ParseIP("192.168.1.189"),
			Gateway:   net.ParseIP("192.168.1.1"),
			DNS:       []net.IP{net.ParseIP("192.168.1.1")},
		},
	}

	err := app.RunConnect("wired", "")
	assert.NoError(t, err)

	output := stdout.String()
	// Should say "wired", not "WiFi"
	assert.Contains(t, output, "Connecting to wired network...")
	assert.NotContains(t, output, "Connecting to WiFi")
	// Should display connection info same as WiFi
	assert.Contains(t, output, "Connected!")
	assert.Contains(t, output, "192.168.1.189")
	assert.Contains(t, output, "192.168.1.1")
}

func TestApp_RunStop_AllServices(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.HotspotMgr = &testHotspotManager{status: &types.HotspotStatus{Running: true}}
	app.DHCPMgr = &testDHCPManager{running: true}

	err := app.RunStop(nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Stopped services")
}

func TestApp_RunStop_SpecificInterface(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunStop([]string{"wlan0"})
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Stopped interface wlan0")
}

func TestApp_RunDNS_SetServers(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunDNS([]string{"8.8.8.8", "8.8.4.4"})
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DNS set to 8.8.8.8, 8.8.4.4")
}

func TestApp_RunDNS_DHCP(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunDNS([]string{"dhcp"})
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DNS restored via DHCP")
}

func TestApp_RunDNS_Error(t *testing.T) {
	app, _, stderr := newTestApp()
	app.NetworkMgr = &testNetworkManager{setDNSErr: errors.New("dns failed")}

	err := app.RunDNS([]string{"8.8.8.8"})
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "dns failed")
}

func TestApp_RunMAC_Success(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.NetworkMgr = &testNetworkManager{mac: "AA:BB:CC:DD:EE:FF"}

	err := app.RunMAC("AA:BB:CC:DD:EE:FF")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "MAC address set to AA:BB:CC:DD:EE:FF")
}

func TestApp_RunMAC_Error(t *testing.T) {
	app, _, stderr := newTestApp()
	app.NetworkMgr = &testNetworkManager{setMACErr: errors.New("mac failed")}

	err := app.RunMAC("invalid")
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "mac failed")
}

func TestApp_RunVPN_List(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.VPNMgr = &testVPNManager{
		vpns: []types.VPNStatus{
			{Name: "work", Type: "wireguard", Connected: true},
		},
	}

	err := app.RunVPN("")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "work (wireguard) - connected")
}

func TestApp_RunVPN_Connect(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunVPN("work")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "VPN connected!")
}

func TestApp_RunVPN_Stop(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunVPN("stop")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "VPN disconnected")
}

func TestApp_RunGenkey_Success(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunGenkey()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "WireGuard keys generated")
	assert.Contains(t, stdout.String(), "privatekey123")
	assert.Contains(t, stdout.String(), "publickey456")
}

func TestApp_RunGenkey_Error(t *testing.T) {
	app, _, stderr := newTestApp()
	app.VPNMgr = &testVPNManager{genkeyErr: errors.New("keygen failed")}

	err := app.RunGenkey()
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "keygen failed")
}

func TestApp_RunShow_AllConfig(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{
				DNS: []string{"1.1.1.1"},
				MAC: "random",
			},
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeNet"},
			},
			VPN: map[string]types.VPNConfig{
				"work": {Type: "wireguard"},
			},
		},
	}

	err := app.RunShow("")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Common Configuration")
	assert.Contains(t, stdout.String(), "Networks")
	assert.Contains(t, stdout.String(), "home")
}

func TestApp_RunShow_SpecificNetwork(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		networkConfig: &types.NetworkConfig{
			SSID: "HomeNet",
			DNS:  []string{"8.8.8.8"},
		},
	}

	err := app.RunShow("home")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Network: home")
	assert.Contains(t, stdout.String(), "HomeNet")
}

func TestApp_RunStatus(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "TestNet", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}
	app.NetworkMgr = &testNetworkManager{
		mac: "AA:BB:CC:DD:EE:FF",
		connectionInfo: &types.Connection{
			Interface: "wlan0",
			SSID:      "TestNet",
			State:     "connected",
			IP:        net.ParseIP("192.168.1.100"),
		},
	}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Network Status")
	// Hostname now comes from os.Hostname() (the real system hostname), not a
	// mocked executor command. Assert the status prints the actual hostname.
	if h, hErr := os.Hostname(); hErr == nil && h != "" {
		assert.Contains(t, stdout.String(), h)
	}
	assert.Contains(t, stdout.String(), "TestNet")
}

func TestApp_RunHotspot_Start(t *testing.T) {
	app, stdout, _ := newTestApp()
	config := &types.HotspotConfig{
		SSID:     "TestHotspot",
		Password: "password123",
		Gateway:  "192.168.50.1",
	}

	err := app.RunHotspot("start", config)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Starting hotspot...")
	assert.Contains(t, stdout.String(), "Hotspot 'TestHotspot' started!")
	assert.Contains(t, stdout.String(), "TestHotspot")
}

func TestApp_RunHotspot_Stop(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunHotspot("stop", nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Hotspot stopped successfully")
}

func TestApp_RunHotspot_Status(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.HotspotMgr = &testHotspotManager{
		status: &types.HotspotStatus{
			Running:   true,
			SSID:      "MyHotspot",
			Interface: "wlan0",
			Gateway:   net.ParseIP("192.168.50.1"),
			Clients:   2,
		},
	}

	err := app.RunHotspot("status", nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Hotspot Status")
	assert.Contains(t, stdout.String(), "MyHotspot")
}

func TestApp_RunHotspot_StartError(t *testing.T) {
	app, _, stderr := newTestApp()
	app.HotspotMgr = &testHotspotManager{startErr: errors.New("start failed")}
	config := &types.HotspotConfig{SSID: "Test"}

	err := app.RunHotspot("start", config)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "Failed to start hotspot")
}

func TestApp_RunDHCPServer_Start(t *testing.T) {
	app, stdout, _ := newTestApp()
	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		LeaseTime: "12h",
	}

	err := app.RunDHCPServer("start", config)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DHCP server started successfully")
}

func TestApp_RunDHCPServer_Stop(t *testing.T) {
	app, stdout, _ := newTestApp()

	err := app.RunDHCPServer("stop", nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DHCP server stopped successfully")
}

func TestApp_RunDHCPServer_Status(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running: true,
		currentConfig: &types.DHCPServerConfig{
			Interface: "eth0",
			Gateway:   "192.168.100.1",
			IPRange:   "192.168.100.50,192.168.100.150",
		},
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "DHCP server is running")
	assert.Contains(t, output, "Interface: eth0")
	assert.Contains(t, output, "Gateway:   192.168.100.1")
	assert.Contains(t, output, "no active leases")
}

func TestApp_RunDHCPServer_StatusWithLeases(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running: true,
		currentConfig: &types.DHCPServerConfig{
			Interface: "eth0",
			Gateway:   "192.168.100.1",
			IPRange:   "192.168.100.50,192.168.100.150",
		},
		leases: []types.DHCPLease{
			{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.100.51", Hostname: "laptop"},
		},
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "aa:bb:cc:dd:ee:ff")
	assert.Contains(t, output, "192.168.100.51")
	assert.Contains(t, output, "laptop")
}

func TestApp_RunDHCPServer_StatusNotRunning(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{running: false}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DHCP server is not running")
}

func TestApp_RunDHCPServer_StartError(t *testing.T) {
	app, _, stderr := newTestApp()
	app.DHCPMgr = &testDHCPManager{startErr: errors.New("start failed")}
	config := &types.DHCPServerConfig{Interface: "eth0"}

	err := app.RunDHCPServer("start", config)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "Failed to start DHCP server")
}

func TestApp_RunDHCPServer_StartNilConfig(t *testing.T) {
	app, _, stderr := newTestApp()

	err := app.RunDHCPServer("start", nil)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "Configuration required")
}

func TestApp_RunDHCPServer_StopError(t *testing.T) {
	app, _, stderr := newTestApp()
	app.DHCPMgr = &testDHCPManager{stopErr: errors.New("stop failed")}

	err := app.RunDHCPServer("stop", nil)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "Failed to stop DHCP server")
}

func TestApp_RunDHCPServer_UnknownAction(t *testing.T) {
	app, _, stderr := newTestApp()

	err := app.RunDHCPServer("restart", nil)
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "Unknown action")
}

func TestApp_RunDHCPServer_StatusShowsIPRange(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running: true,
		currentConfig: &types.DHCPServerConfig{
			Interface: "enp3s0",
			Gateway:   "10.0.0.1",
			IPRange:   "10.0.0.50,10.0.0.150",
		},
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "Interface: enp3s0")
	assert.Contains(t, output, "Gateway:   10.0.0.1")
	assert.Contains(t, output, "IP Range:  10.0.0.50,10.0.0.150")
}

func TestApp_RunDHCPServer_StatusNoConfig(t *testing.T) {
	// Running but currentConfig is nil (edge case — e.g., process detected but not started by us)
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running:       true,
		currentConfig: nil,
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "DHCP server is running")
	// Should not crash, just skip config display
	assert.NotContains(t, output, "Interface:")
	assert.Contains(t, output, "no active leases")
}

func TestApp_RunDHCPServer_StatusMultipleLeases(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running: true,
		currentConfig: &types.DHCPServerConfig{
			Interface: "eth0",
			Gateway:   "192.168.100.1",
			IPRange:   "192.168.100.50,192.168.100.150",
		},
		leases: []types.DHCPLease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.51", Hostname: "laptop"},
			{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.100.52", Hostname: ""},
			{MAC: "aa:bb:cc:dd:ee:03", IP: "192.168.100.53", Hostname: "phone"},
		},
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()

	// Table header
	assert.Contains(t, output, "MAC")
	assert.Contains(t, output, "IP")
	assert.Contains(t, output, "HOSTNAME")
	assert.Contains(t, output, "EXPIRES")

	// All three leases
	assert.Contains(t, output, "aa:bb:cc:dd:ee:01")
	assert.Contains(t, output, "192.168.100.51")
	assert.Contains(t, output, "laptop")
	assert.Contains(t, output, "aa:bb:cc:dd:ee:02")
	assert.Contains(t, output, "192.168.100.52")
	assert.Contains(t, output, "-") // empty hostname renders as "-"
	assert.Contains(t, output, "aa:bb:cc:dd:ee:03")
	assert.Contains(t, output, "phone")

	// Should NOT show "no active leases"
	assert.NotContains(t, output, "no active leases")
}

func TestApp_RunDHCPServer_StatusLeaseError(t *testing.T) {
	// GetLeases returns error — should still show running status, just no table
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{
		running: true,
		currentConfig: &types.DHCPServerConfig{
			Interface: "eth0",
			Gateway:   "192.168.100.1",
			IPRange:   "192.168.100.50,192.168.100.150",
		},
		leasesErr: errors.New("permission denied"),
	}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "DHCP server is running")
	assert.Contains(t, output, "no active leases")
}

func TestApp_RunDHCPServer_StartShowsConfig(t *testing.T) {
	app, stdout, _ := newTestApp()
	config := &types.DHCPServerConfig{
		Interface: "enp3s0",
		Gateway:   "10.0.0.1",
		IPRange:   "10.0.0.50,10.0.0.150",
		LeaseTime: "6h",
	}

	err := app.RunDHCPServer("start", config)
	assert.NoError(t, err)
	output := stdout.String()
	assert.Contains(t, output, "Interface: enp3s0")
	assert.Contains(t, output, "Gateway:   10.0.0.1")
	assert.Contains(t, output, "IP Range:  10.0.0.50,10.0.0.150")
	assert.Contains(t, output, "Lease:     6h")
}

// Tests for resolveVPNName and attemptVPNConnect (converted from the former
// TestApp_connectVPN_* suite when connectVPN was inlined into RunConnect)

func TestApp_resolveVPNName_NetworkSpecificVPN(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
	}
	assert.Equal(t, "work-vpn", app.resolveVPNName("work"))
}

func TestApp_resolveVPNName_CommonVPN(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"}, // No VPN configured
			},
		},
	}
	assert.Equal(t, "default-vpn", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_NetworkVPNOverridesCommon(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
	}
	assert.Equal(t, "work-vpn", app.resolveVPNName("work"))
}

func TestApp_resolveVPNName_NoConfig(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: nil}
	assert.Equal(t, "", app.resolveVPNName("any"))
}

func TestApp_resolveVPNName_NoVPNConfigured(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"},
			},
		},
	}
	assert.Equal(t, "", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_VPNExplicitlyDisabled(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"}, // Common VPN is set
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"}, // VPN field empty, but explicitly disabled
			},
		},
		vpnExplicitlyDisabled: map[string]bool{
			"home": true, // Simulate vpn: (empty) in YAML
		},
	}
	// Must NOT inherit common VPN because vpn: was explicitly set to empty
	assert.Equal(t, "", app.resolveVPNName("home"))
}

func TestApp_resolveVPNName_UnconfiguredNameFallsBackToCommon(t *testing.T) {
	// The plain-SSID path: RunConnect passes the SSID as configName when the
	// name isn't a configured network — common.vpn must still apply
	// (the second success path of the old connectVPN).
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{VPN: "default-vpn"}},
	}
	assert.Equal(t, "default-vpn", app.resolveVPNName("any"))
}

func TestApp_resolveVPNName_NilConfigMgr(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = nil
	assert.Equal(t, "", app.resolveVPNName("any"))
}

func TestApp_attemptVPNConnect_ConnectionError(t *testing.T) {
	app, stdout, stderr := newTestApp()
	app.VPNMgr = &testVPNManager{connectErr: errors.New("connection refused")}

	app.attemptVPNConnect("broken-vpn")
	// VPN connection failure should show warning to user but not fail WiFi connection
	assert.NotContains(t, stdout.String(), "VPN connected")
	assert.Contains(t, stderr.String(), "VPN connection failed")
}

// End-to-end characterizations through RunConnect: unit tests on
// resolveVPNName can stay green while the RunConnect wiring is broken
// (hint without connect, wrong configName), so the two inheritance edges
// that motivated the refactor are asserted through the full command.

func TestApp_RunConnect_NetworkVPNOverridesCommonEndToEnd(t *testing.T) {
	app, _, _ := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", VPN: "work-vpn"},
			},
		},
		networkConfig: &types.NetworkConfig{SSID: "WorkWiFi", VPN: "work-vpn"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("work", "")
	assert.NoError(t, err)
	assert.True(t, tracker.connectCalled)
	assert.Equal(t, "work-vpn", tracker.lastConnectName)
}

func TestApp_RunConnect_VPNExplicitlyDisabledEndToEnd(t *testing.T) {
	app, _, _ := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{VPN: "default-vpn"},
			Networks: map[string]types.NetworkConfig{
				"home": {SSID: "HomeWiFi"},
			},
		},
		networkConfig:         &types.NetworkConfig{SSID: "HomeWiFi"},
		vpnExplicitlyDisabled: map[string]bool{"home": true},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.False(t, tracker.connectCalled, "vpn: (explicitly empty) must not inherit common.vpn")
}

func TestApp_RunConnect_WithVPNIntegration(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.NoVPN = false
	app.ConfigMgr = &testConfigManager{
		networkErr: errors.New("not configured"), // Force direct SSID path
		config: &types.Config{
			Common: types.CommonConfig{VPN: "auto-vpn"},
		},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "TestSSID", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("TestSSID", "password")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
	assert.Contains(t, stdout.String(), "Connecting to VPN 'auto-vpn'...")
	assert.Contains(t, stdout.String(), "VPN connected!")
}

func TestApp_RunConnect_NoVPNFlag(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.NoVPN = true // VPN disabled
	app.ConfigMgr = &testConfigManager{
		networkErr: errors.New("not configured"),
		config: &types.Config{
			Common: types.CommonConfig{VPN: "auto-vpn"},
		},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "TestSSID", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("TestSSID", "password")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
	assert.NotContains(t, stdout.String(), "VPN connected") // VPN should not be attempted
}

func TestApp_RunConnect_MergesWithCommon(t *testing.T) {
	cfgMgr := &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{
				DNS:      []string{"8.8.8.8"},
				MAC:      "random",
				Hostname: "myhost",
			},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi", PSK: "secret"},
			},
		},
		networkConfig: &types.NetworkConfig{SSID: "WorkWiFi", PSK: "secret"},
	}
	app, stdout, _ := newTestApp()
	app.ConfigMgr = cfgMgr
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "WorkWiFi", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("work", "")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
	// Verify MergeWithCommon was called
	assert.True(t, cfgMgr.mergeWithCommonCalled, "MergeWithCommon should be called for configured networks")
	assert.Equal(t, "work", cfgMgr.lastMergedNetwork)
}

func TestApp_RunShow_MergesWithCommon(t *testing.T) {
	cfgMgr := &testConfigManager{
		config: &types.Config{
			Common: types.CommonConfig{
				DNS: []string{"8.8.8.8", "8.8.4.4"},
				MAC: "random",
			},
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi"},
			},
		},
		networkConfig: &types.NetworkConfig{SSID: "WorkWiFi"},
	}
	app, stdout, _ := newTestApp()
	app.ConfigMgr = cfgMgr

	err := app.RunShow("work")
	assert.NoError(t, err)
	// Verify MergeWithCommon was called and common settings were merged
	assert.True(t, cfgMgr.mergeWithCommonCalled)
	assert.Equal(t, "work", cfgMgr.lastMergedNetwork)
	// Verify merged DNS is shown in output
	assert.Contains(t, stdout.String(), "8.8.8.8")
}

// trackingVPNManager tracks Disconnect and Connect calls
type trackingVPNManager struct {
	testVPNManager
	disconnectCalled bool
	connectCalled    bool
	lastConnectName  string
}

func (v *trackingVPNManager) Disconnect(name string) error {
	v.disconnectCalled = true
	return nil
}

func (v *trackingVPNManager) Connect(name string) error {
	v.connectCalled = true
	v.lastConnectName = name
	return nil
}

func TestApp_RunConnect_DisconnectsActiveVPNFirst(t *testing.T) {
	app, _, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	// Create a custom VPN manager that tracks disconnect calls
	vpnMgr := &trackingVPNManager{}
	app.VPNMgr = vpnMgr

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.True(t, vpnMgr.disconnectCalled, "should disconnect active VPN before connecting")
}

func TestMaskSecret(t *testing.T) {
	// Short secrets are fully masked
	assert.Equal(t, "****", maskSecret("abc"))
	assert.Equal(t, "****", maskSecret("abcd"))

	// Longer secrets show first 2 and last 2 characters
	assert.Equal(t, "se****12", maskSecret("secret12"))
	assert.Equal(t, "my**rd", maskSecret("myword"))
	assert.Equal(t, "lo************34", maskSecret("longpassword1234"))
}

func TestApp_RunShow_MasksPSK(t *testing.T) {
	cfgMgr := &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{
				"work": {SSID: "WorkWiFi"},
			},
		},
		networkConfig: &types.NetworkConfig{SSID: "WorkWiFi", PSK: "supersecretpassword"},
	}
	app, stdout, _ := newTestApp()
	app.ConfigMgr = cfgMgr

	err := app.RunShow("work")
	assert.NoError(t, err)
	// PSK should be shown but masked
	assert.Contains(t, stdout.String(), "PSK:")
	assert.NotContains(t, stdout.String(), "supersecretpassword")
	assert.Contains(t, stdout.String(), "su***************rd") // masked version
}

// --- Task 4: net portal command tests ---

// testPortalDetector returns results in sequence, repeating the last one.
// err applies to every call; errs (when set) is a per-call error sequence
// (indexed like results, repeating the last entry) and overrides err.
type testPortalDetector struct {
	results []types.PortalResult
	err     error
	errs    []error
	calls   int
}

func (d *testPortalDetector) Check() (types.PortalResult, error) {
	d.calls++
	i := d.calls - 1
	if len(d.errs) > 0 {
		j := i
		if j >= len(d.errs) {
			j = len(d.errs) - 1
		}
		if d.errs[j] != nil {
			return types.PortalResult{}, d.errs[j]
		}
	} else if d.err != nil {
		return types.PortalResult{}, d.err
	}
	if len(d.results) == 0 {
		return types.PortalResult{}, nil
	}
	if i >= len(d.results) {
		i = len(d.results) - 1
	}
	return d.results[i], nil
}

// portalTestApp is newTestApp with a LOADED (empty) config: RunPortal treats
// a nil config as "config failed to load" (exit 3), so RunPortal tests other
// than NoDetector/ConfigLoadFailure need a non-nil one.
func portalTestApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	app, stdout, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}}
	return app, stdout, stderr
}

func TestApp_RunPortal_ConfigLoadFailure(t *testing.T) {
	// nil config = load failure: error out (exit 3), don't probe defaults —
	// silently probing the DEFAULT URL would mask the user's broken config.
	app, _, stderr := newTestApp() // testConfigManager{} → GetConfig() == nil
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.PortalDet = det

	_, err := app.RunPortal()
	assert.Error(t, err)
	assert.Equal(t, 0, det.calls, "must not probe with defaults when config failed to load")
	assert.Contains(t, stderr.String(), "configuration failed to load")
}

func TestApp_RunPortal_OnlineNamesDefaultRouteIface(t *testing.T) {
	app, stdout, _ := portalTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, status)
	assert.Contains(t, stdout.String(), "Internet: ok (default IPv4 route: eth0)")
}

func TestApp_RunPortal_Online(t *testing.T) {
	app, stdout, _ := portalTestApp()
	app.RouteMgr = nil // pinned: expected string is the route-unlabeled form
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOnline, status)
	assert.Contains(t, stdout.String(), "Internet: ok")
}

func TestApp_RunPortal_PortalWithLoginURL(t *testing.T) {
	app, stdout, _ := portalTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Captive portal detected")
	assert.Contains(t, stdout.String(), "Log in at: http://portal.example.com/login")
}

func TestApp_RunPortal_PortalWithoutLoginURL(t *testing.T) {
	app, stdout, _ := portalTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:   types.PortalStatusPortal,
		ProbeURL: "http://probe.example.com/",
	}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Contains(t, stdout.String(), "Open http://probe.example.com/ in a browser")
}

func TestApp_RunPortal_Offline(t *testing.T) {
	app, stdout, _ := portalTestApp()
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusOffline, status)
	assert.Contains(t, stdout.String(), "Internet: unreachable")
}

func TestApp_RunPortal_IgnoresCheckOff(t *testing.T) {
	// check: off disables AUTOMATIC probes (connect/status) only — the
	// explicit `net portal` command must always probe. Locks the contract
	// against a future "cleanup" that gates all entry points on
	// portalCheckEnabled.
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
	}
	det := &testPortalDetector{results: []types.PortalResult{{
		Status: types.PortalStatusPortal, PortalURL: "http://portal.example.com/login", ProbeURL: "http://p",
	}}}
	app.PortalDet = det

	status, err := app.RunPortal()
	assert.NoError(t, err)
	assert.Equal(t, types.PortalStatusPortal, status)
	assert.Equal(t, 1, det.calls)
	assert.Contains(t, stdout.String(), "Captive portal detected")
}

func TestApp_RunPortal_NoDetector(t *testing.T) {
	app, _, _ := newTestApp() // PortalDet nil
	_, err := app.RunPortal()
	assert.Error(t, err)
}

func TestApp_RunPortal_DetectorError(t *testing.T) {
	app, _, stderr := portalTestApp()
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	_, err := app.RunPortal()
	assert.Error(t, err)
	assert.Contains(t, stderr.String(), "probe URL must be plain http")
}

// --- Task 5: connect + status integration tests ---

func TestApp_RunConnect_PortalWarning(t *testing.T) {
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.Contains(t, stderr.String(), "http://portal.example.com/login")
	// No VPN configured → no VPN hint
	assert.NotContains(t, stderr.String(), "VPN")
}

func TestApp_RunConnect_PortalCheckOff(t *testing.T) {
	app, _, stderr := newTestApp()
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p"}}}
	app.PortalDet = det
	app.ConfigMgr = &testConfigManager{
		config:     &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
		networkErr: errors.New("not found"),
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 0, det.calls, "portal check must be skipped when check: off")
	assert.NotContains(t, stderr.String(), "captive portal")
}

func TestApp_RunConnect_NilDetectorNoCrash(t *testing.T) {
	app, stdout, _ := newTestApp() // PortalDet nil — must not panic
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
}

func TestApp_RunConnect_PortalStillConnectsVPN(t *testing.T) {
	app, _, stderr := newTestApp()
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{
			Networks: map[string]types.NetworkConfig{"home": {SSID: "Home", VPN: "myvpn"}},
			VPN:      map[string]types.VPNConfig{"myvpn": {Type: "wireguard"}},
		},
		networkConfig: &types.NetworkConfig{SSID: "Home", VPN: "myvpn"},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p",
	}}}

	err := app.RunConnect("home", "")
	assert.NoError(t, err)
	assert.True(t, tracker.connectCalled, "VPN attempt must still happen after portal warning")
	assert.Equal(t, "myvpn", tracker.lastConnectName)
	assert.Contains(t, stderr.String(), "may not come up until")
}

func TestApp_RunConnect_OfflineRetriesOnce(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	// First probe races DHCP/DNS settling and reports Offline; retry sees the portal.
	det := &testPortalDetector{results: []types.PortalResult{
		{Status: types.PortalStatusOffline},
		{Status: types.PortalStatusPortal, PortalURL: "http://portal.example.com/login", ProbeURL: "http://p"},
	}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.Contains(t, stderr.String(), "captive portal detected")
	assert.NotContains(t, stderr.String(), "no internet connectivity")
}

func TestApp_RunConnect_OnlineAfterSettleRetry(t *testing.T) {
	// Offline then Online: the settle-retry succeeded — no warning at all.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{results: []types.PortalResult{
		{Status: types.PortalStatusOffline},
		{Status: types.PortalStatusOnline},
	}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.NotContains(t, stderr.String(), "Warning:")
}

func TestApp_RunConnect_OfflineAfterRetryWarns(t *testing.T) {
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.Contains(t, stderr.String(), "no internet connectivity")
}

func TestApp_RunConnect_MultiHomedNotePicksLowestMetric(t *testing.T) {
	// TWO defaults, dump order deliberately wlan0-first: the note must
	// compare against the lowest-metric (preferred) default, eth0@100 —
	// not whatever the netlink dump lists first.
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "192.168.1.1", Iface: "wlan0", Metric: 600},
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stderr.String(), "default route (eth0)")
	assert.Contains(t, stderr.String(), "Disable/unplug eth0")
	assert.Contains(t, stderr.String(), "wlan0")
}

func TestApp_RunConnect_MultiHomedNoteOnAnyOutcome(t *testing.T) {
	// A portal/offline verdict via the wrong link misleads just like a false
	// "ok" — the note must print regardless of the probe outcome.
	for _, result := range []types.PortalResult{
		{Status: types.PortalStatusPortal, PortalURL: "http://x", ProbeURL: "http://p"},
		{Status: types.PortalStatusOffline},
	} {
		app, _, stderr := newTestApp()
		app.PortalRetryDelay = time.Millisecond
		app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
		app.WiFiMgr = &testWiFiManager{
			connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
		}
		app.PortalDet = &testPortalDetector{results: []types.PortalResult{result}}
		app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
			{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
		}}

		err := app.RunConnect("TestSSID", "password123")
		assert.NoError(t, err)
		assert.Contains(t, stderr.String(), "default route (eth0)", "outcome %v", result.Status)
	}
}

func TestApp_RunConnect_NoMultiHomedNoteWhenRoutesMatch(t *testing.T) {
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "192.168.1.1", Iface: "wlan0", Metric: 600},
	}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.NotContains(t, stderr.String(), "default route (")
}

func TestApp_RunConnect_MisconfiguredProbeWarns(t *testing.T) {
	// A Check() error means misconfiguration — must be visible on stderr,
	// not silently swallowed (a silent skip looks like "no portal").
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err) // still non-fatal
	assert.Contains(t, stderr.String(), "portal probe misconfigured")
}

func TestApp_RunConnect_RetryErrorNoOfflineWarning(t *testing.T) {
	// First probe offline, retry errors out: don't warn "offline" off a
	// half-completed check.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{
		results: []types.PortalResult{{Status: types.PortalStatusOffline}},
		errs:    []error{nil, errors.New("transient")},
	}
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 2, det.calls)
	assert.NotContains(t, stderr.String(), "no internet connectivity")
}

func TestApp_RunStatus_ProbeErrorLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.RouteMgr = nil                                          // pinned: expected string is the route-unlabeled form
	app.PortalDet = &testPortalDetector{err: errors.New("probe URL must be plain http")}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  probe error")
}

func TestApp_RunStatus_ShowsInternetLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.RouteMgr = nil                                          // pinned: expected string is the route-unlabeled form
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status:    types.PortalStatusPortal,
		PortalURL: "http://portal.example.com/login",
		ProbeURL:  "http://probe.example.com/",
	}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  captive portal (http://portal.example.com/login)")
	assert.Equal(t, 1, app.PortalDet.(*testPortalDetector).calls, "status probes exactly once (no retry)")
}

func TestApp_RunStatus_OnlineLabeledHostWide(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.RouteMgr = nil                                          // pinned: expected string is the route-unlabeled form
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  ok (default route)")
}

func TestApp_RunStatus_PortalNamesDefaultRouteIface(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{
		Status: types.PortalStatusPortal, PortalURL: "http://portal.example.com/login", ProbeURL: "http://p",
	}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  captive portal (http://portal.example.com/login) (default IPv4 route: eth0)")
}

func TestApp_RunStatus_UnreachableNamesDefaultRouteIface(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  unreachable (default IPv4 route: eth0)")
}

func TestApp_RunStatus_OnlineNamesDefaultRouteIface(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.RouteMgr = &fakenetlink.RouteManager{Routes: []types.Route{
		{Dst: "default", Gw: "10.0.0.1", Iface: "eth0", Metric: 100},
	}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  ok (default IPv4 route: eth0)")
}

func TestApp_RunStatus_UnknownStatusNeverOk(t *testing.T) {
	// Zero-value PortalResult (PortalStatusUnknown) must never print "ok".
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.PortalDet = &testPortalDetector{}                       // empty results → zero-value result

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  unreachable")
	assert.NotContains(t, stdout.String(), "Internet:  ok")
}

func TestApp_RunConnect_VPNConfiguredSuppressesOfflineWarning(t *testing.T) {
	// VPN-required networks legitimately look offline pre-VPN: no scary
	// warning, but the VPN attempt must still proceed.
	app, _, stderr := newTestApp()
	app.PortalRetryDelay = time.Millisecond
	tracker := &trackingVPNManager{}
	app.VPNMgr = tracker
	app.ConfigMgr = &testConfigManager{
		config:     &types.Config{Common: types.CommonConfig{VPN: "default-vpn"}},
		networkErr: errors.New("not found"),
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.NotContains(t, stderr.String(), "no internet connectivity")
	assert.True(t, tracker.connectCalled)
}

func TestApp_RunStatus_InternetLineWhenDisconnected(t *testing.T) {
	// The Internet line is host-wide (#42): it must print even when the
	// selected interface has no connection info (another link may carry
	// the internet). Guards the insertion point staying OUTSIDE the
	// connected-branch if/else.
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.NetworkMgr = &testNetworkManager{connectionErr: errors.New("no connection on iface")}
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	// Prove the disconnected branch actually ran (guards a no-op
	// connectionErr harness) AND the host-wide line still printed.
	assert.NotContains(t, stdout.String(), "State:     connected")
	assert.Contains(t, stdout.String(), "Internet:  ok (default route")
}

func TestApp_RunStatus_ConfigLoadFailureSkipsProbe(t *testing.T) {
	// Load failure means the user's portal policy (check: off, custom URL)
	// is unknown — auto-probing substituted defaults could report "ok"
	// against their intent. Skip; the loader already surfaced the error.
	app, stdout, _ := newTestApp() // testConfigManager{} → GetConfig() == nil
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.PortalDet = det

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Equal(t, 0, det.calls)
	assert.NotContains(t, stdout.String(), "Internet:")
}

func TestApp_RunConnect_UnknownStatusWarns(t *testing.T) {
	// Zero-value PortalResult (Unknown) must fail closed on connect too —
	// a silent no-op reads as a clean connect with working internet.
	app, _, stderr := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}, networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")}},
	}
	det := &testPortalDetector{} // empty results → zero-value result
	app.PortalDet = det

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Equal(t, 1, det.calls) // Unknown is not Offline: no settle-retry
	assert.Contains(t, stderr.String(), "could not be determined")
}

func TestApp_RunStatus_OfflineLine(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.ConfigMgr = &testConfigManager{config: &types.Config{}} // loaded config: auto-probe allowed
	app.PortalDet = &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOffline}}}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Internet:  unreachable")
}

func TestApp_RunStatus_PortalCheckOffSkipsProbe(t *testing.T) {
	app, stdout, _ := newTestApp()
	det := &testPortalDetector{results: []types.PortalResult{{Status: types.PortalStatusOnline}}}
	app.PortalDet = det
	app.ConfigMgr = &testConfigManager{
		config: &types.Config{Common: types.CommonConfig{Portal: types.PortalConfig{Check: "off"}}},
	}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Equal(t, 0, det.calls)
	assert.NotContains(t, stdout.String(), "Internet:")
}
