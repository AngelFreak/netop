package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

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
	config        *types.Config
	networkConfig *types.NetworkConfig
	networkErr    error
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
	mac        string
	setMACErr  error
	setDNSErr  error
	dhcpErr    error
	connectErr error
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

func (n *testNetworkManager) DHCPRenew(iface, hostname string) error {
	return n.dhcpErr
}

func (n *testNetworkManager) ConnectToConfiguredNetwork(config *types.NetworkConfig, password string, wifiMgr types.WiFiManager) error {
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

func (n *testNetworkManager) SetIP(iface, addr, gateway string) error {
	return nil
}

func (n *testNetworkManager) GetConnectionInfo(iface string) (*types.Connection, error) {
	return nil, nil
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
	running   bool
	startErr  error
	stopErr   error
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
	assert.Contains(t, stdout.String(), "Network1")
	assert.Contains(t, stdout.String(), "OpenNet")
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
	app.ConfigMgr = &testConfigManager{networkErr: errors.New("not found")}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", IP: net.ParseIP("192.168.1.100")},
		},
	}

	err := app.RunConnect("TestSSID", "password123")
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Connected!")
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
	assert.Contains(t, stdout.String(), "Connected!")
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
	assert.Contains(t, stdout.String(), "VPN connected (work)")
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
	app.Executor = &testExecutor{
		executeFunc: func(name string, args ...string) (string, error) {
			if name == "hostname" {
				return "testhost\n", nil
			}
			return "", nil
		},
	}
	app.WiFiMgr = &testWiFiManager{
		connections: []types.Connection{
			{Interface: "wlan0", SSID: "TestNet", State: "connected", IP: net.ParseIP("192.168.1.100")},
		},
	}
	app.NetworkMgr = &testNetworkManager{mac: "AA:BB:CC:DD:EE:FF"}

	err := app.RunStatus()
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "Network Status")
	assert.Contains(t, stdout.String(), "testhost")
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
	assert.Contains(t, stdout.String(), "Hotspot started successfully")
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
	app, stdout, _ := newTestApp()
	app.HotspotMgr = &testHotspotManager{startErr: errors.New("start failed")}
	config := &types.HotspotConfig{SSID: "Test"}

	err := app.RunHotspot("start", config)
	assert.Error(t, err)
	assert.Contains(t, stdout.String(), "Failed to start hotspot")
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
	app.DHCPMgr = &testDHCPManager{running: true}

	err := app.RunDHCPServer("status", nil)
	assert.NoError(t, err)
	assert.Contains(t, stdout.String(), "DHCP server is running")
}

func TestApp_RunDHCPServer_StartError(t *testing.T) {
	app, stdout, _ := newTestApp()
	app.DHCPMgr = &testDHCPManager{startErr: errors.New("start failed")}
	config := &types.DHCPServerConfig{Interface: "eth0"}

	err := app.RunDHCPServer("start", config)
	assert.Error(t, err)
	assert.Contains(t, stdout.String(), "Failed to start DHCP server")
}
