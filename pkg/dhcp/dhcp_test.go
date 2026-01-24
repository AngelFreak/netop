package dhcp

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
	commands map[string]string
	errors   map[string]error
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		commands: make(map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockExecutor) Execute(cmd string, args ...string) (string, error) {
	fullCmd := cmd
	for _, arg := range args {
		fullCmd += " " + arg
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
func setupTestManager() (*dhcpManagerImpl, *mockExecutor) {
	executor := newMockExecutor()
	logger := &mockLogger{}
	mgr := NewDHCPManager(executor, logger).(*dhcpManagerImpl)

	// Use temp files for testing
	tmpDir := os.TempDir()
	mgr.dnsmasqPidFile = filepath.Join(tmpDir, "test_dnsmasq_dhcp.pid")
	mgr.dnsmasqConfFile = filepath.Join(tmpDir, "test_dnsmasq_dhcp.conf")

	return mgr, executor
}

func cleanup(mgr *dhcpManagerImpl) {
	os.Remove(mgr.dnsmasqPidFile)
	os.Remove(mgr.dnsmasqConfFile)
}

// Tests
func TestNewDHCPManager(t *testing.T) {
	executor := newMockExecutor()
	logger := &mockLogger{}

	mgr := NewDHCPManager(executor, logger)

	assert.NotNil(t, mgr)
}

func TestStart_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		DNS:       []string{"8.8.8.8"},
		LeaseTime: "24h",
	}

	// Mock successful commands
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
	assert.NotNil(t, mgr.currentConfig)
	assert.Equal(t, "eth0", mgr.currentConfig.Interface)

	// Verify configuration file was created
	assert.FileExists(t, mgr.dnsmasqConfFile)
}

func TestStart_InvalidConfig(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	tests := []struct {
		name   string
		config *types.DHCPServerConfig
		errMsg string
	}{
		{
			name:   "missing interface",
			config: &types.DHCPServerConfig{Gateway: "192.168.1.1", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "interface is required",
		},
		{
			name:   "missing gateway",
			config: &types.DHCPServerConfig{Interface: "eth0", IPRange: "192.168.1.50,192.168.1.150"},
			errMsg: "gateway is required",
		},
		{
			name:   "missing IP range",
			config: &types.DHCPServerConfig{Interface: "eth0", Gateway: "192.168.1.1"},
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

func TestStart_AlreadyRunning(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	// Simulate running process by creating PID file pointing to PID 1
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	// Mock commands
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestStart_InterfaceDownFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.errors["ip link set eth0 down"] = fmt.Errorf("operation not permitted")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to bring interface down")
}

func TestStart_DnsmasqFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
	}

	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = ""
	executor.errors[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = fmt.Errorf("dnsmasq failed")

	err := mgr.Start(config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start dnsmasq")
}

func TestStop_Success(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
	}

	// Create mock PID file pointing to PID 1
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	executor.commands["kill 1"] = ""
	executor.commands["ip addr flush dev eth0"] = ""
	executor.commands["ip link set eth0 down"] = ""

	err := mgr.Stop()

	assert.NoError(t, err)
	assert.Nil(t, mgr.currentConfig)
	assert.NoFileExists(t, mgr.dnsmasqPidFile)
}

func TestStop_NotRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestStop_KillFails(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	mgr.currentConfig = &types.DHCPServerConfig{
		Interface: "eth0",
	}

	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)

	executor.errors["kill 1"] = fmt.Errorf("no such process")

	err := mgr.Stop()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stop dnsmasq")
}

func TestIsRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	// Test when not running
	assert.False(t, mgr.IsRunning())

	// Test when running
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)
	assert.True(t, mgr.IsRunning())
}

func TestGenerateDnsmasqConfig_WithCustomDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
		DNS:       []string{"1.1.1.1", "1.0.0.1"},
		LeaseTime: "24h",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=eth0")
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,24h")
	assert.Contains(t, content, "server=1.1.1.1")
	assert.Contains(t, content, "server=1.0.0.1")
	assert.Contains(t, content, "dhcp-option=3,192.168.100.1")
	assert.Contains(t, content, "dhcp-option=6,1.1.1.1,1.0.0.1")
}

func TestGenerateDnsmasqConfig_WithDefaultDNS(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interface=eth0")
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,12h")
	assert.Contains(t, content, "server=8.8.8.8")
	assert.Contains(t, content, "server=8.8.4.4")
	assert.Contains(t, content, "dhcp-option=6,8.8.8.8,8.8.4.4")
}

func TestGenerateDnsmasqConfig_CustomLeaseTime(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		IPRange:   "192.168.100.50,192.168.100.150",
		Gateway:   "192.168.100.1",
		LeaseTime: "1h",
	}

	err := mgr.generateDnsmasqConfig(config)
	assert.NoError(t, err)

	data, err := os.ReadFile(mgr.dnsmasqConfFile)
	assert.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "dhcp-range=192.168.100.50,192.168.100.150,1h")
}

func TestDnsmasqRunning(t *testing.T) {
	mgr, _ := setupTestManager()
	defer cleanup(mgr)

	// Test when PID file doesn't exist
	assert.False(t, mgr.dnsmasqRunning())

	// Test when PID file exists but process doesn't
	os.WriteFile(mgr.dnsmasqPidFile, []byte("99999"), 0644)
	assert.False(t, mgr.dnsmasqRunning())

	// Test when PID file exists and process exists
	os.WriteFile(mgr.dnsmasqPidFile, []byte("1"), 0644)
	assert.True(t, mgr.dnsmasqRunning())
}

// Tests for configurable netmask (Issue 6 fix)

func TestStart_WithCustomNetmask(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "10.0.0.1",
		IPRange:   "10.0.0.50,10.0.0.150",
		Netmask:   "16", // Use /16 instead of default /24
	}

	// Mock successful commands with custom netmask
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 10.0.0.1/16 dev eth0"] = "" // Should use /16 not /24
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
}

func TestStart_WithDefaultNetmask(t *testing.T) {
	mgr, executor := setupTestManager()
	defer cleanup(mgr)

	config := &types.DHCPServerConfig{
		Interface: "eth0",
		Gateway:   "192.168.100.1",
		IPRange:   "192.168.100.50,192.168.100.150",
		// Netmask not specified - should default to /24
	}

	// Mock successful commands
	executor.commands["ip link set eth0 down"] = ""
	executor.commands["ip link set eth0 up"] = ""
	executor.commands["ip addr add 192.168.100.1/24 dev eth0"] = "" // Should default to /24
	executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

	err := mgr.Start(config)

	assert.NoError(t, err)
}

func TestStart_WithDifferentNetmasks(t *testing.T) {
	tests := []struct {
		name     string
		netmask  string
		expected string
	}{
		{"classA", "8", "/8"},
		{"classB", "16", "/16"},
		{"classC", "24", "/24"},
		{"slash25", "25", "/25"},
		{"slash28", "28", "/28"},
		{"slash30", "30", "/30"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, executor := setupTestManager()
			defer cleanup(mgr)

			config := &types.DHCPServerConfig{
				Interface: "eth0",
				Gateway:   "10.0.0.1",
				IPRange:   "10.0.0.50,10.0.0.150",
				Netmask:   tt.netmask,
			}

			// Mock successful commands
			executor.commands["ip link set eth0 down"] = ""
			executor.commands["ip link set eth0 up"] = ""
			executor.commands["ip addr add 10.0.0.1"+tt.expected+" dev eth0"] = ""
			executor.commands[fmt.Sprintf("dnsmasq -C %s -x %s", mgr.dnsmasqConfFile, mgr.dnsmasqPidFile)] = ""

			err := mgr.Start(config)
			assert.NoError(t, err)
		})
	}
}
