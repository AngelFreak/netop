package hotspot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Mock implementations
type mockExecutor struct {
	commands  map[string]string
	errors    map[string]error
	callbacks map[string]func() // Callbacks to run when command is executed
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands:  make(map[string]string),
		errors:    make(map[string]error),
		callbacks: make(map[string]func()),
	}
}

func (m *mockExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
	}

	// Run callback if registered (e.g., to create PID files)
	if cb, ok := m.callbacks[fullCmd]; ok {
		cb()
	}

	// Check for errors first
	if err, hasErr := m.errors[fullCmd]; hasErr {
		output := ""
		if val, ok := m.commands[fullCmd]; ok {
			output = val
		}
		return output, err
	}

	if output, ok := m.commands[fullCmd]; ok {
		return output, nil
	}
	return "", nil
}

func (m *mockExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockExecutor) HasCommand(cmd string) bool {
	return true // mock always has the command
}

type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

// Test helpers
func setupTestManager() (*hotspotManagerImpl, *mockExecutor) {
	executor := newMockExecutor()
	logger := &mockLogger{}
	mgr := NewHotspotManager(executor, logger).(*hotspotManagerImpl)

	// Use temp files for testing
	tmpDir := os.TempDir()
	mgr.hostapdPidFile = filepath.Join(tmpDir, "test_hostapd.pid")
	mgr.dnsmasqPidFile = filepath.Join(tmpDir, "test_dnsmasq.pid")
	mgr.hostapdConfFile = filepath.Join(tmpDir, "test_hostapd.conf")
	mgr.dnsmasqConfFile = filepath.Join(tmpDir, "test_dnsmasq.conf")

	return mgr, executor
}

func cleanup(mgr *hotspotManagerImpl) {
	os.Remove(mgr.hostapdPidFile)
	os.Remove(mgr.dnsmasqPidFile)
	os.Remove(mgr.hostapdConfFile)
	os.Remove(mgr.dnsmasqConfFile)
}

// Tests
func TestNewHotspotManager(t *testing.T) {
	executor := newMockExecutor()
	logger := &mockLogger{}

	mgr := NewHotspotManager(executor, logger)

	assert.NotNil(t, mgr)
}

func TestStart_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Password:  "testpass123",
		Channel:   6,
		Gateway:   "192.168.50.1",
		IPRange:   "192.168.50.50,192.168.50.150",
		DNS:       []string{"8.8.8.8"},
	}

	// Mock successful commands
	executor.commands["ip link set wlan0 down"] = ""
	executor.commands["iw wlan0 set type __ap"] = ""
	executor.commands["ip link set wlan0 up"] = ""
	executor.commands["ip addr add 192.168.50.1/24 dev wlan0"] = ""
	executor.commands["ip route show default"] = "default via 192.168.1.1 dev eth0"
	executor.commands["sh -c echo 1 > /proc/sys/net/ipv4/ip_forward"] = ""
	executor.commands["iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"] = ""
	executor.commands["iptables -A FORWARD -i wlan0 -j ACCEPT"] = ""
	executor.commands["iptables -A FORWARD -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT"] = ""

	hostapdCmd := fmt.Sprintf("hostapd -B -P %s %s", mgr.hostapdPidFile, mgr.hostapdConfFile)
	dnsmasqCmd := fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)

	executor.commands[hostapdCmd] = ""
	executor.commands[dnsmasqCmd] = ""

	// Simulate hostapd creating PID file when the command is executed
	// Use PID 1 (init) which always exists
	executor.callbacks[hostapdCmd] = func() {
		os.WriteFile(mgr.hostapdPidFile, []byte("1"), 0644)
	}
	executor.callbacks[dnsmasqCmd] = func() {
		os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)
	}

	err := mgr.Start(config)

	assert.NoError(t, err)
	assert.NotNil(t, mgr.currentConfig)
	assert.Equal(t, "TestAP", mgr.currentConfig.SSID)

	// Verify configuration files were created
	assert.FileExists(t, mgr.hostapdConfFile)
	assert.FileExists(t, mgr.dnsmasqConfFile)
}

func TestStart_InvalidConfig(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tests := []struct {
		name   string
		config *types.HotspotConfig
		errMsg string
	}{
		{
			name:   "missing interface",
			config: &types.HotspotConfig{SSID: "Test", Password: "testpass123", Channel: 6, Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "interface is required",
		},
		{
			name:   "missing SSID",
			config: &types.HotspotConfig{Interface: "wlan0", Password: "testpass123", Channel: 6, Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "SSID is required",
		},
		{
			name:   "short password",
			config: &types.HotspotConfig{Interface: "wlan0", SSID: "Test", Password: "short", Channel: 6, Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "password must be at least 8 characters",
		},
		{
			name:   "invalid channel low",
			config: &types.HotspotConfig{Interface: "wlan0", SSID: "Test", Password: "testpass123", Channel: 0, Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "invalid channel",
		},
		{
			name:   "invalid channel 5GHz gap",
			config: &types.HotspotConfig{Interface: "wlan0", SSID: "Test", Password: "testpass123", Channel: 30, Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "invalid channel",
		},
		{
			name:   "missing gateway",
			config: &types.HotspotConfig{Interface: "wlan0", SSID: "Test", Password: "testpass123", Channel: 6, IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "gateway is required",
		},
		{
			name:   "missing IP range",
			config: &types.HotspotConfig{Interface: "wlan0", SSID: "Test", Password: "testpass123", Channel: 6, Gateway: "192.168.1.1"},
			errMsg: "IP range is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Start(tt.config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestValidChannel(t *testing.T) {
	// Valid 2.4GHz channels
	for _, ch := range []int{1, 6, 11, 13, 14} {
		assert.True(t, isValidChannel(ch), "channel %d should be valid", ch)
	}

	// Valid 5GHz channels
	for _, ch := range []int{36, 40, 44, 48, 149, 153, 157, 161, 165} {
		assert.True(t, isValidChannel(ch), "channel %d should be valid", ch)
	}

	// Invalid channels
	for _, ch := range []int{0, 15, 30, 35, 37, 200} {
		assert.False(t, isValidChannel(ch), "channel %d should be invalid", ch)
	}
}

func TestStart_AlreadyRunning(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Password:  "testpass123",
		Channel:   6,
		Gateway:   "192.168.50.1",
		IPRange:   "192.168.50.50,192.168.50.150",
	}

	// Simulate running processes by creating PID files pointing to existing processes
	// Use PID 1 (init/systemd) which always exists
	os.WriteFile(mgr.hostapdPidFile, []byte("1"), 0644)
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	// Mock commands
	executor.commands["ip link set wlan0 down"] = ""

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStart_InterfaceDownFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Password:  "testpass123",
		Channel:   6,
		Gateway:   "192.168.50.1",
		IPRange:   "192.168.50.50,192.168.50.150",
	}

	executor.errors["ip link set wlan0 down"] = fmt.Errorf("operation not permitted")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to bring interface down")
}

func TestStart_HostapdFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Password:  "testpass123",
		Channel:   6,
		Gateway:   "192.168.50.1",
		IPRange:   "192.168.50.50,192.168.50.150",
	}

	executor.commands["ip link set wlan0 down"] = ""
	executor.commands["iw wlan0 set type __ap"] = ""
	executor.commands["ip link set wlan0 up"] = ""
	executor.commands["ip addr add 192.168.50.1/24 dev wlan0"] = ""
	executor.errors[fmt.Sprintf("hostapd -B -P %s %s", mgr.hostapdPidFile, mgr.hostapdConfFile)] = fmt.Errorf("hostapd failed")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start hostapd")
}

func TestStop_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Gateway:   "192.168.50.1",
	}

	// Create mock PID files pointing to PID 1 (always exists)
	os.WriteFile(mgr.hostapdPidFile, []byte("1"), 0644)
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	executor.commands["kill 1"] = ""
	executor.commands["ip addr flush dev wlan0"] = ""
	executor.commands["ip link set wlan0 down"] = ""
	executor.commands["iw wlan0 set type managed"] = ""
	executor.commands["ip link set wlan0 up"] = ""

	err := mgr.Stop()

	assert.NoError(t, err)
	assert.Nil(t, mgr.currentConfig)
	assert.NoFileExists(t, mgr.hostapdPidFile)
	assert.NoFileExists(t, mgr.dnsmasqPidFile)
}

func TestStop_NotRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestStop_PartialFailure(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.HotspotConfig{
		Interface: "wlan0",
	}

	os.WriteFile(mgr.hostapdPidFile, []byte("1"), 0644)
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	executor.commands["kill 1"] = ""
	executor.errors["kill 1"] = fmt.Errorf("no such process")
	executor.commands["ip addr flush dev wlan0"] = ""
	executor.commands["ip link set wlan0 down"] = ""
	executor.commands["iw wlan0 set type managed"] = ""
	executor.commands["ip link set wlan0 up"] = ""

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hostapd")
}

func TestGetStatus(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	// Test when not running
	status, err := mgr.GetStatus()
	assert.NoError(t, err)
	assert.False(t, status.Running)

	// Test when running
	mgr.currentConfig = &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Gateway:   "192.168.50.1",
	}

	os.WriteFile(mgr.hostapdPidFile, []byte("1"), 0644)
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	executor.commands["iw dev wlan0 station dump"] = `Station aa:bb:cc:dd:ee:ff (on wlan0)
	inactive time:	304 ms
Station 11:22:33:44:55:66 (on wlan0)
	inactive time:	104 ms`

	status, err = mgr.GetStatus()
	assert.NoError(t, err)
	assert.True(t, status.Running)
	assert.Equal(t, "wlan0", status.Interface)
	assert.Equal(t, "TestAP", status.SSID)
	assert.Equal(t, 2, status.Clients)
}

func TestGetConnectedClients(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.HotspotConfig{
		Interface: "wlan0",
	}

	executor.commands["iw dev wlan0 station dump"] = `Station aa:bb:cc:dd:ee:ff (on wlan0)
	inactive time:	304 ms
	rx bytes:	12345
Station 11:22:33:44:55:66 (on wlan0)
	inactive time:	104 ms
	rx bytes:	67890`

	clients, err := mgr.getConnectedClients()
	assert.NoError(t, err)
	assert.Equal(t, 2, clients)
}

func TestGetConnectedClients_Error(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.HotspotConfig{
		Interface: "wlan0",
	}

	executor.errors["iw dev wlan0 station dump"] = fmt.Errorf("interface not found")

	_, err := mgr.getConnectedClients()
	assert.Error(t, err)
}

func TestGenerateHostapdConfig_WithPassword(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "TestAP",
		Password:  "testpass123",
		Channel:   6,
	}

	err := mgr.generateHostapdConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.hostapdConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=wlan0")
	assert.Contains(t, content, "ssid=TestAP")
	assert.Contains(t, content, "channel=6")
	assert.Contains(t, content, "wpa=2")
	assert.Contains(t, content, "wpa_passphrase=testpass123")
}

func TestGenerateHostapdConfig_NoPassword(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "OpenAP",
		Channel:   11,
	}

	err := mgr.generateHostapdConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.hostapdConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=wlan0")
	assert.Contains(t, content, "ssid=OpenAP")
	assert.Contains(t, content, "channel=11")
	assert.Contains(t, content, "hw_mode=g") // 2.4GHz
	assert.NotContains(t, content, "wpa=2")
}

func TestGenerateHostapdConfig_5GHz(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		SSID:      "5GHz-AP",
		Password:  "testpass123",
		Channel:   36, // 5GHz channel
	}

	err := mgr.generateHostapdConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.hostapdConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "hw_mode=a") // 5GHz mode
	assert.Contains(t, content, "channel=36")
}

func TestGenerateDnsmasqConfig(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		IPRange:   "192.168.50.50,192.168.50.150",
		Gateway:   "192.168.50.1",
		DNS:       []string{"8.8.8.8", "1.1.1.1"},
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=wlan0")
	assert.Contains(t, content, "dhcp-range=192.168.50.50,192.168.50.150,12h")
	assert.Contains(t, content, "server=8.8.8.8")
	assert.Contains(t, content, "server=1.1.1.1")
	assert.Contains(t, content, "dhcp-option=3,192.168.50.1")
	assert.Contains(t, content, "dhcp-option=6,8.8.8.8,1.1.1.1")
}

func TestGenerateDnsmasqConfig_NoDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.HotspotConfig{
		Interface: "wlan0",
		IPRange:   "192.168.50.50,192.168.50.150",
		Gateway:   "192.168.50.1",
		DNS:       []string{}, // Empty DNS - should use defaults
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	// Should use default DNS servers
	assert.Contains(t, content, "server=8.8.8.8")
	assert.Contains(t, content, "server=8.8.4.4")
	assert.Contains(t, content, "dhcp-option=6,8.8.8.8,8.8.4.4")
}

func TestGetDnsmasqLeases(t *testing.T) {
	tmpFile := filepath.Join(os.TempDir(), "test_leases")
	defer os.Remove(tmpFile)

	leaseData := `1635123456 aa:bb:cc:dd:ee:ff 192.168.50.100 client1 *
1635123457 11:22:33:44:55:66 192.168.50.101 client2 *`

	os.WriteFile(tmpFile, []byte(leaseData), 0644)

	leases, err := GetDnsmasqLeases(tmpFile)
	assert.NoError(t, err)
	assert.Len(t, leases, 2)
}

func TestParseDnsmasqLease(t *testing.T) {
	lease := "1635123456 aa:bb:cc:dd:ee:ff 192.168.50.100 client1 *"

	timestamp, mac, ip, hostname, err := ParseDnsmasqLease(lease)
	assert.NoError(t, err)
	assert.Equal(t, int64(1635123456), timestamp)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
	assert.Equal(t, "192.168.50.100", ip)
	assert.Equal(t, "client1", hostname)
}

func TestParseDnsmasqLease_Invalid(t *testing.T) {
	lease := "invalid lease format"

	_, _, _, _, err := ParseDnsmasqLease(lease)
	assert.Error(t, err)
}

func TestEscapeHostapdString(t *testing.T) {
	t.Run("escapes backslashes", func(t *testing.T) {
		result := escapeHostapdString(`test\path`)
		assert.Equal(t, `test\\path`, result)
	})

	t.Run("escapes newlines", func(t *testing.T) {
		result := escapeHostapdString("test\nvalue")
		assert.Equal(t, `test\nvalue`, result)
	})

	t.Run("escapes carriage returns", func(t *testing.T) {
		result := escapeHostapdString("test\rvalue")
		assert.Equal(t, `test\rvalue`, result)
	})

	t.Run("escapes combined special characters", func(t *testing.T) {
		result := escapeHostapdString("test\\\n\rvalue")
		assert.Equal(t, `test\\\n\rvalue`, result)
	})

	t.Run("leaves normal strings unchanged", func(t *testing.T) {
		result := escapeHostapdString("normal-ssid-123")
		assert.Equal(t, "normal-ssid-123", result)
	})
}

func TestGenerateHostapdConfig_EscapesSpecialCharacters(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	t.Run("escapes newlines in SSID to prevent injection", func(t *testing.T) {
		config := &types.HotspotConfig{
			Interface: "wlan0",
			SSID:      "Evil\nwpa=0",
			Password:  "testpass123",
			Channel:   6,
		}

		err := mgr.generateHostapdConfig(config)
		assert.NoError(t, err)

		data, err := os.ReadFile(mgr.hostapdConfFile)
		assert.NoError(t, err)

		content := string(data)
		// The newline should be escaped, not creating a new line
		assert.Contains(t, content, `ssid=Evil\nwpa=0`)
		// Should NOT have wpa=0 as a separate config line from injection
		assert.NotContains(t, content, "\nwpa=0\n")
	})

	t.Run("escapes newlines in password to prevent injection", func(t *testing.T) {
		config := &types.HotspotConfig{
			Interface: "wlan0",
			SSID:      "TestAP",
			Password:  "pass123\nwpa=0",
			Channel:   6,
		}

		err := mgr.generateHostapdConfig(config)
		assert.NoError(t, err)

		data, err := os.ReadFile(mgr.hostapdConfFile)
		assert.NoError(t, err)

		content := string(data)
		// The newline should be escaped in the password
		assert.Contains(t, content, `wpa_passphrase=pass123\nwpa=0`)
	})

	t.Run("escapes backslashes in SSID", func(t *testing.T) {
		config := &types.HotspotConfig{
			Interface: "wlan0",
			SSID:      `Test\AP`,
			Password:  "testpass123",
			Channel:   6,
		}

		err := mgr.generateHostapdConfig(config)
		assert.NoError(t, err)

		data, err := os.ReadFile(mgr.hostapdConfFile)
		assert.NoError(t, err)

		content := string(data)
		assert.Contains(t, content, `ssid=Test\\AP`)
	})
}
